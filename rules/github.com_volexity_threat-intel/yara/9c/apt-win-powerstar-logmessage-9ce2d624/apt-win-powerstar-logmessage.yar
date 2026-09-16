rule apt_win_powerstar_logmessage : CharmingKitten
{
    meta:
        author = "threatintel@volexity.com"
        date = "2023-05-16"
        description = "Detects interesting log message embedded in memory only version of PowerStar."
        memory_suitable = 1
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

    strings:
        $s_1 = "wau, ije ulineun mueos-eul halkkayo?"
    condition:
        all of them
}