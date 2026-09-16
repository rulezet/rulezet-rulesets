rule apt_win_powerstar_lnk : CharmingKitten
{
    meta:
        author = "threatintel@volexity.com"
        date = "2023-05-16"
        description = "Detects LNK command line used to install PowerStar."
        memory_suitable = 1
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

    strings:
        $p_1 = "-UseBasicParsing).Content; &(gcm i*x)$"

        $c_1 = "powershecde43ell.ecde43exe"
        $c_2 = "wgcde43eet -Ucde43eri"
        $c_3 = "-UseBasicde43ecParsing).Contcde43eent; &(gcm i*x)$"
    condition:
        any of them
}