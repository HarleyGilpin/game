package gg.rsmod.game.message.handler

import gg.rsmod.game.action.PawnPathAction
import gg.rsmod.game.message.MessageHandler
import gg.rsmod.game.message.impl.OpNpc1Message
import gg.rsmod.game.model.World
import gg.rsmod.game.model.attr.INTERACTING_NPC_ATTR
import gg.rsmod.game.model.attr.INTERACTING_OPT_ATTR
import gg.rsmod.game.model.entity.Client
import gg.rsmod.game.model.priv.Privilege
import java.lang.ref.WeakReference

/**
 * @author Tom <rspsmods@gmail.com>
 */
class OpNpc1Handler : MessageHandler<OpNpc1Message> {
    override fun handle(
        client: Client,
        world: World,
        message: OpNpc1Message,
    ) {
        val npc = world.npcs[message.index] ?: return

        if (!client.lock.canNpcInteract()) {
            return
        }

        log(client, "Npc option 1: index=%d, movement=%d, npc=%s", message.index, message.movementType, npc)

        client.writeConsoleMessage("Npc option 1: index=${message.index}, movement=${message.movementType}, npc=$npc")

        if (message.movementType == 1 && world.privileges.isEligible(client.privilege, Privilege.ADMIN_POWER)) {
            client.moveTo(world.findRandomTileAround(npc.tile, 1) ?: npc.tile)
        }

        client.closeInterfaceModal()
        client.fullInterruption(movement = true, interactions = true, queue = true)

        client.attr[INTERACTING_OPT_ATTR] = 1
        client.attr[INTERACTING_NPC_ATTR] = WeakReference(npc)
        client.executePlugin(PawnPathAction.walkPlugin)
    }
}
