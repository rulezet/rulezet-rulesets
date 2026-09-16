rule rule_nanorobeus_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'nanorobeus' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nanorobeus"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_nanorobeus_offensive_tool_keyword = /\skekeo\/modules\/kull_m_memory\.c/ nocase ascii wide
                        $string2_nanorobeus_offensive_tool_keyword = " kerberoast /spn:" nocase ascii wide
                        $string3_nanorobeus_offensive_tool_keyword = " tgtdeleg /spn:cifs" nocase ascii wide
                        $string4_nanorobeus_offensive_tool_keyword = /\/kerberoast\.c/ nocase ascii wide
                        $string5_nanorobeus_offensive_tool_keyword = /\/modules\/kull_m_crypto_system\.h/
                        $string6_nanorobeus_offensive_tool_keyword = /\/nanorobeus\.git/ nocase ascii wide
                        $string7_nanorobeus_offensive_tool_keyword = /\\include\\kerberoast\.h/ nocase ascii wide
                        $string8_nanorobeus_offensive_tool_keyword = /\\kerberoast\.c/ nocase ascii wide
                        $string9_nanorobeus_offensive_tool_keyword = /\\kerberoast\.c/ nocase ascii wide
                        $string10_nanorobeus_offensive_tool_keyword = /\\nanorobeus\-main\.zip/ nocase ascii wide
                        $string11_nanorobeus_offensive_tool_keyword = /\\sample_brc4\.json/ nocase ascii wide
                        $string12_nanorobeus_offensive_tool_keyword = /\\sample_sliver\.json/ nocase ascii wide
                        $string13_nanorobeus_offensive_tool_keyword = /dist.{0,1000}_brc4\.x64\.o/ nocase ascii wide
                        $string14_nanorobeus_offensive_tool_keyword = /dist.{0,1000}_brc4\.x86\.o/ nocase ascii wide
                        $string15_nanorobeus_offensive_tool_keyword = /dist\/nanorobeus_cs\./ nocase ascii wide
                        $string16_nanorobeus_offensive_tool_keyword = /nanorobeus.{0,1000}_cs\.x64\./ nocase ascii wide
                        $string17_nanorobeus_offensive_tool_keyword = /nanorobeus.{0,1000}_cs\.x86\./ nocase ascii wide
                        $string18_nanorobeus_offensive_tool_keyword = /nanorobeus.{0,1000}dump/ nocase ascii wide
                        $string19_nanorobeus_offensive_tool_keyword = /nanorobeus\.cna/ nocase ascii wide
                        $string20_nanorobeus_offensive_tool_keyword = /nanorobeus\.x64/ nocase ascii wide
                        $string21_nanorobeus_offensive_tool_keyword = /nanorobeus\.x86/ nocase ascii wide
                        $string22_nanorobeus_offensive_tool_keyword = "nanorobeus_brc4" nocase ascii wide
                        $string23_nanorobeus_offensive_tool_keyword = "nanorobeus64" nocase ascii wide
                        $string24_nanorobeus_offensive_tool_keyword = "nanorobeus86" nocase ascii wide
                        $string25_nanorobeus_offensive_tool_keyword = "nanorobeus-main" nocase ascii wide
                        $string26_nanorobeus_offensive_tool_keyword = /sample_brc4\.json/ nocase ascii wide
                        $string27_nanorobeus_offensive_tool_keyword = "wavvs/nanorobeus" nocase ascii wide

    condition:
        any of them
}