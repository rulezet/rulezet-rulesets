rule apt_win_powerstar_decrypt_function : CharmingKitten
{
    meta:
        author = "threatintel@volexity.com"
        date = "2023-05-16"
        description = "Detects PowerStar decrypt function, potentially downloaded standalone and then injected."
        hash1 = "b79d28fe5e3c988bb5aadb12ce442d53291dbb9ede0c7d9d64eec078beba5585"
        memory_suitable = 1
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

    strings:
        $f_1 = "function Borjol{"

        $s_1 = "$global:Domain = \""
        $s_2 = "$global:IP = \""
        $s_3 = "$global:yeolsoe"
        $s_4 = "$semii.Close()"
        $s_5 = "$cemii.Close()"
        $s_6 = "$memii.Close()"
    condition:
        any of ($f_*) or
        2 of ($s_*)

}