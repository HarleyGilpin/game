package gg.rsmod.game.sync.segment

import gg.rsmod.game.model.entity.Player
import gg.rsmod.game.sync.SynchronizationSegment
import gg.rsmod.net.packet.GamePacketBuilder

/**
 * @author Tom <rspsmods@gmail.com>
 */
class PlayerTeleportSegment(
    private val other: Player,
    private val encodeUpdateBlocks: Boolean,
) : SynchronizationSegment {
    override fun encode(buf: GamePacketBuilder) {
        /*
         * Signal to the client that [other] needs to be decoded.
         */
        buf.putBits(1, 1)
        /*
         * Does [other] have pending [gg.rsmod.game.sync.block.UpdateBlockType]s?
         */
        buf.putBit(encodeUpdateBlocks)
        /*
         * Signal to the client that [other] has been moved without actual
         * walking being involved.
         */
        buf.putBits(2, 3)

        /*
         * The difference from [other]'s last tile as far as [player]'s client is
         * concerned.
         */
        var diffX = other.tile.x - (other.lastTile?.x ?: 0)
        var diffZ = other.tile.z - (other.lastTile?.z ?: 0)
        var diffH = other.tile.height - (other.lastTile?.height ?: 0)

        /*
         * If the move is within a short radius, we want to save some bandwidth.
         */
        if (Math.abs(diffX) <= Player.NORMAL_VIEW_DISTANCE && Math.abs(diffZ) <= Player.NORMAL_VIEW_DISTANCE) {
            /*
             * Signal to the client that the difference in tiles are within
             * viewing distance.
             */
            buf.putBits(1, 0)
            /*
             * Write the difference in tiles.
             */

            if (diffX < 0) {
                diffX += 32
            }

            if (diffZ < 0) {
                diffZ += 32
            }

            buf.putBits(12, (diffZ and 0x1f) or (diffX and 0x1f shl 5) or (diffH and 0x3 shl 10))
        } else {
            /*
             * Signal to the client that the difference in tiles are not within
             * viewing distance.
             */
            buf.putBits(1, 1)
            /*
             * Write the difference in tiles.
             */
            buf.putBits(30, (diffZ and 0x3FFF) + (diffX and 0x3FFF shl 14) + (diffH and 0x3 shl 28))
        }
    }
}
