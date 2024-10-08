package gg.rsmod.plugins.content.skills.smithing.data

import gg.rsmod.plugins.api.cfg.Items

enum class BarType(
    val item: Int,
    val experience: Double,
    val barName: String,
    val levelRequired: Int,
) {
    BRONZE(
        item = Items.BRONZE_BAR,
        experience = 12.5,
        barName = "Bronze Smithing",
        levelRequired = 1,
    ),
    BLURITE(
        item = Items.BLURITE_BAR,
        experience = 16.0,
        barName = "Blurite Smithing",
        levelRequired = 8,
    ),
    IRON(
        item = Items.IRON_BAR,
        experience = 25.0,
        barName = "Iron Smithing",
        levelRequired = 15,
    ),
    STEEL(
        item = Items.STEEL_BAR,
        experience = 37.5,
        barName = "Steel Smithing",
        levelRequired = 20,
    ),
    MITHRIL(
        item = Items.MITHRIL_BAR,
        experience = 50.0,
        barName = "Mithril Smithing",
        levelRequired = 50,
    ),
    ADAMANT(
        item = Items.ADAMANT_BAR,
        experience = 62.5,
        barName = "Adamant Smithing",
        levelRequired = 70,
    ),
    RUNITE(
        item = Items.RUNE_BAR,
        experience = 75.0,
        barName = "Runite Smithing",
        levelRequired = 85,
    ),
    ;

    companion object {
        val values = enumValues<BarType>()
    }
}
