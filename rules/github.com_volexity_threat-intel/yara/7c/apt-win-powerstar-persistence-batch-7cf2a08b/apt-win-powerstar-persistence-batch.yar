rule apt_win_powerstar_persistence_batch : CharmingKitten
{
    meta:
        author = "threatintel@volexity.com"
        date = "2023-05-16"
        description = "Detects the batch script used to persist PowerStar via Startup."
        hash1 = "9777f106ac62829cd3cfdbc156100fe892cfc4038f4c29a076e623dc40a60872"
        memory_suitable = 1
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

    strings:
        $s_1 = "e^c^h^o o^f^f"
        $s_2 = "powershertxdll.ertxdxe"
        $s_3 = "Get-Conrtxdtent -Prtxdath"
        $s_4 = "%appdata%\\Microsrtxdoft\\Windortxdws\\"
        $s_5 = "&(gcm i*x)$"
    condition:
        3 of them
}