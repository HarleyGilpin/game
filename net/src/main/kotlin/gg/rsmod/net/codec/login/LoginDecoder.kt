package gg.rsmod.net.codec.login

import gg.rsmod.net.codec.StatefulFrameDecoder
import gg.rsmod.util.io.BufferUtils.readString
import gg.rsmod.util.io.Xtea
import io.netty.buffer.ByteBuf
import io.netty.buffer.Unpooled
import io.netty.channel.ChannelFutureListener
import io.netty.channel.ChannelHandlerContext
import mu.KLogging
import java.math.BigInteger

/**
 * @author Tom <rspsmods@gmail.com>
 */
class LoginDecoder(
    private val serverRevision: Int,
    private val cacheCrcs: IntArray,
    private val serverSeed: Long,
    private val rsaExponent: BigInteger?,
    private val rsaModulus: BigInteger?,
) : StatefulFrameDecoder<LoginDecoderState>(LoginDecoderState.HANDSHAKE) {
    private var payloadLength = -1

    private var reconnecting = false

    override fun decode(
        ctx: ChannelHandlerContext,
        buf: ByteBuf,
        out: MutableList<Any>,
        state: LoginDecoderState,
    ) {
        buf.markReaderIndex()
        when (state) {
            LoginDecoderState.HANDSHAKE -> decodeHandshake(ctx, buf)
            LoginDecoderState.HEADER -> decodeHeader(ctx, buf, out)
            LoginDecoderState.SERVER_SEED -> Unit
        }
    }

    private fun decodeHandshake(
        ctx: ChannelHandlerContext,
        buf: ByteBuf,
    ) {
        if (buf.isReadable) {
            val opcode = buf.readByte().toInt()
            if (opcode == LOGIN_OPCODE || opcode == RECONNECT_OPCODE) {
                reconnecting = opcode == RECONNECT_OPCODE
                setState(LoginDecoderState.HEADER)
            } else {
                ctx.writeResponse(LoginResultType.BAD_SESSION_ID)
            }
        }
    }

    private fun decodeHeader(
        ctx: ChannelHandlerContext,
        buf: ByteBuf,
        out: MutableList<Any>,
    ) {
        if (buf.readableBytes() >= 3) {
            val size = buf.readUnsignedShort()
            if (buf.readableBytes() >= size) {
                val revision = buf.readInt()
                if (revision == serverRevision) {
                    decodePayload(ctx, buf, out)
                } else {
                    ctx.writeResponse(LoginResultType.REVISION_MISMATCH)
                }
            } else {
                buf.resetReaderIndex()
            }
        }
    }

    private fun validateUsername(username: String): Boolean {
        val regex = Regex("^(?=.{1,12}$)[a-zA-Z0-9]+(?: [a-zA-Z0-9]+)*$")
        return regex.matches(username)
    }

    private fun decodePayload(
        ctx: ChannelHandlerContext,
        buf: ByteBuf,
        out: MutableList<Any>,
    ) {
        buf.markReaderIndex()

        val opcode = buf.readUnsignedByte().toInt()
        logger.info { "Opcode: $opcode" }

        val secureBuf: ByteBuf =
            if (rsaExponent != null && rsaModulus != null) {
                val secureBufLength = buf.readUnsignedShort()
                logger.info { "Secure buffer length: $secureBufLength" }
                val secureBytes = ByteArray(secureBufLength)
                buf.readBytes(secureBytes)
                logger.info { "Secure bytes: ${secureBytes.contentToString()}" }
                val rsaValue = BigInteger(secureBytes).modPow(rsaExponent, rsaModulus)
                logger.info { "RSA value: ${rsaValue.toByteArray().contentToString()}" }
                Unpooled.wrappedBuffer(rsaValue.toByteArray())
            } else {
                buf
            }

        val successfulEncryption = secureBuf.readUnsignedByte().toInt() == 10
        logger.info { "Successful encryption: $successfulEncryption" }
        if (!successfulEncryption) {
            buf.resetReaderIndex()
            logger.info("Channel '{}' login request rejected.", ctx.channel())
            ctx.writeResponse(LoginResultType.BAD_SESSION_ID)
            return
        }

        val xteaKeys = IntArray(4)
        for (i in xteaKeys.indices) {
            xteaKeys[i] = secureBuf.readInt()
            logger.info { "XTEA key $i: ${xteaKeys[i]}" }
        }

        secureBuf.readLong()

        val password: String?
        val previousXteaKeys = IntArray(4)

        if (reconnecting) {
            for (i in previousXteaKeys.indices) {
                previousXteaKeys[i] = secureBuf.readInt()
                logger.info { "Previous XTEA key $i: ${previousXteaKeys[i]}" }
            }
            password = null
        } else {
            password = secureBuf.readString()
            logger.info { "Password: $password" }
        }

        val xteaBuf = buf.decipher(xteaKeys)
        val username = xteaBuf.readString().trim()
        logger.info { "Username: $username" }

        if (!validateUsername(username)) {
            ctx.writeResponse(LoginResultType.INVALID_CREDENTIALS)
            return
        }

        val clientSettings = xteaBuf.readByte().toInt()
        val displayMode = xteaBuf.readUnsignedByte().toInt() // Modes: 1 = Fixed, 2 = Resizeable, 3 = Fullscreen
        val clientResizable = displayMode == 2
        val clientWidth = xteaBuf.readUnsignedShort()
        val clientHeight = xteaBuf.readUnsignedShort()
        logger.info {
            "Width: $clientWidth, Height: $clientHeight, clientSettings: $clientSettings, displayMode: $displayMode, " +
                "clientResizable: $clientResizable"
        }

        val request =
            LoginRequest(
                channel = ctx.channel(),
                username = username,
                password = password ?: "",
                revision = serverRevision,
                xteaKeys = xteaKeys,
                resizableClient = clientResizable,
                auth = -1,
                uuid = "".uppercase(),
                clientWidth = clientWidth,
                clientHeight = clientHeight,
                reconnecting = reconnecting,
            )
        out.add(request)
    }

    private fun ChannelHandlerContext.writeResponse(result: LoginResultType) {
        val buf = channel().alloc().buffer(1)
        buf.writeByte(result.id)
        writeAndFlush(buf).addListener(ChannelFutureListener.CLOSE)
    }

    private fun ByteBuf.decipher(xteaKeys: IntArray): ByteBuf {
        val data = ByteArray(readableBytes())
        readBytes(data)
        return Unpooled.wrappedBuffer(Xtea.decipher(xteaKeys, data, 0, data.size))
    }

    companion object : KLogging() {
        private const val LOGIN_OPCODE = 16
        private const val RECONNECT_OPCODE = 18
    }
}
