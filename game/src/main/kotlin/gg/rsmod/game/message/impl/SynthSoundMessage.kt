package gg.rsmod.game.message.impl

import gg.rsmod.game.message.Message

/**
 * @author Tom <rspsmods@gmail.com>
 */
data class SynthSoundMessage(
    val sound: Int,
    val volume: Int,
    val delay: Int,
    val unknownByte: Int = 255,
    val unknownShort: Int = 256,
) : Message
