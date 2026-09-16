rule rule_Nuages_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Nuages' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Nuages"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Nuages_offensive_tool_keyword = /\snuages\.formatImplantLastSeen/ nocase ascii wide
                        $string2_Nuages_offensive_tool_keyword = " NuagesImplant" nocase ascii wide
                        $string3_Nuages_offensive_tool_keyword = "!autoruns " nocase ascii wide
                        $string4_Nuages_offensive_tool_keyword = "!files upload " nocase ascii wide
                        $string5_Nuages_offensive_tool_keyword = "!handlers load " nocase ascii wide
                        $string6_Nuages_offensive_tool_keyword = "!implants " nocase ascii wide
                        $string7_Nuages_offensive_tool_keyword = "!modules load " nocase ascii wide
                        $string8_Nuages_offensive_tool_keyword = /\!put\s.{0,1000}\/tmp/ nocase ascii wide
                        $string9_Nuages_offensive_tool_keyword = "!tunnels --tcp" nocase ascii wide
                        $string10_Nuages_offensive_tool_keyword = /\!use\s.{0,1000}aes256_py/ nocase ascii wide
                        $string11_Nuages_offensive_tool_keyword = /\!use\s.{0,1000}reflected_assembly/ nocase ascii wide
                        $string12_Nuages_offensive_tool_keyword = "/implant/callback" nocase ascii wide
                        $string13_Nuages_offensive_tool_keyword = "/Nuages_Cli" nocase ascii wide
                        $string14_Nuages_offensive_tool_keyword = /\/nuagesAPI\.js/ nocase ascii wide
                        $string15_Nuages_offensive_tool_keyword = /\\Nuages_Cli/ nocase ascii wide
                        $string16_Nuages_offensive_tool_keyword = "before-create-implant-callback" nocase ascii wide
                        $string17_Nuages_offensive_tool_keyword = "before-create-implant-io-bin" nocase ascii wide
                        $string18_Nuages_offensive_tool_keyword = "before-find-implant-chunks" nocase ascii wide
                        $string19_Nuages_offensive_tool_keyword = /DNSAES256Handler\./ nocase ascii wide
                        $string20_Nuages_offensive_tool_keyword = /http.{0,1000}127\.0\.0\.1\:3030/ nocase ascii wide
                        $string21_Nuages_offensive_tool_keyword = /http.{0,1000}localhost\:3030/ nocase ascii wide
                        $string22_Nuages_offensive_tool_keyword = /HTTPAES256Handler\./ nocase ascii wide
                        $string23_Nuages_offensive_tool_keyword = /implant\-callback\./ nocase ascii wide
                        $string24_Nuages_offensive_tool_keyword = /Nuages.{0,1000}\/Implants/ nocase ascii wide
                        $string25_Nuages_offensive_tool_keyword = /nuages\.clearImplants\s/ nocase ascii wide
                        $string26_Nuages_offensive_tool_keyword = /nuages\.getAutoruns/ nocase ascii wide
                        $string27_Nuages_offensive_tool_keyword = /nuages\.getImplants/ nocase ascii wide
                        $string28_Nuages_offensive_tool_keyword = /nuages\.getListeners/ nocase ascii wide
                        $string29_Nuages_offensive_tool_keyword = /nuages\.printImplants/ nocase ascii wide
                        $string30_Nuages_offensive_tool_keyword = /nuages\.printListeners/ nocase ascii wide
                        $string31_Nuages_offensive_tool_keyword = /nuages_cli\.js/ nocase ascii wide
                        $string32_Nuages_offensive_tool_keyword = "NuagesC2Connector" nocase ascii wide
                        $string33_Nuages_offensive_tool_keyword = "NuagesC2Implant" nocase ascii wide
                        $string34_Nuages_offensive_tool_keyword = "NuagesPythonImplant" nocase ascii wide
                        $string35_Nuages_offensive_tool_keyword = "NuagesSharpImplant" nocase ascii wide
                        $string36_Nuages_offensive_tool_keyword = "p3nt4/Nuages" nocase ascii wide
                        $string37_Nuages_offensive_tool_keyword = "posh_in_mem" nocase ascii wide
                        $string38_Nuages_offensive_tool_keyword = "processImplantMessage" nocase ascii wide
                        $string39_Nuages_offensive_tool_keyword = "runFakeTerminal" nocase ascii wide
                        $string40_Nuages_offensive_tool_keyword = /SLACKAES256Handler\./ nocase ascii wide
                        $string41_Nuages_offensive_tool_keyword = /Utils\\Posh\.cs/ nocase ascii wide

    condition:
        any of them
}