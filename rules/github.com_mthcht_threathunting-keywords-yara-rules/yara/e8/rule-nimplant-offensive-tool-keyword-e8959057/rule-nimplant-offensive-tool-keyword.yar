rule rule_nimplant_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'nimplant' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nimplant"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_nimplant_offensive_tool_keyword = " -d:sleepmask" nocase ascii wide
                        $string2_nimplant_offensive_tool_keyword = " exe-selfdelete" nocase ascii wide
                        $string3_nimplant_offensive_tool_keyword = " --nomain -d:exportDll --passL:" nocase ascii wide
                        $string4_nimplant_offensive_tool_keyword = /\.nimplant/ nocase ascii wide
                        $string5_nimplant_offensive_tool_keyword = /\.ShellcodeRDI/ nocase ascii wide
                        $string6_nimplant_offensive_tool_keyword = /\/NimPlant\./ nocase ascii wide
                        $string7_nimplant_offensive_tool_keyword = "/NimPlant/" nocase ascii wide
                        $string8_nimplant_offensive_tool_keyword = "/nimplants/" nocase ascii wide
                        $string9_nimplant_offensive_tool_keyword = /\\NimPlant\./ nocase ascii wide
                        $string10_nimplant_offensive_tool_keyword = "_nimplant_" nocase ascii wide
                        $string11_nimplant_offensive_tool_keyword = /127\.0\.0\.1\:31337/ nocase ascii wide
                        $string12_nimplant_offensive_tool_keyword = "789CF3CBCC0DC849CC2B51703652084E2D2A4B2D02003B5C0650" nocase ascii wide
                        $string13_nimplant_offensive_tool_keyword = "BeaconGetSpawnTo" nocase ascii wide
                        $string14_nimplant_offensive_tool_keyword = "BeaconInjectProcess" nocase ascii wide
                        $string15_nimplant_offensive_tool_keyword = "C2 Client" nocase ascii wide
                        $string16_nimplant_offensive_tool_keyword = "C2 Nimplant Server" nocase ascii wide
                        $string17_nimplant_offensive_tool_keyword = "Cannot enumerate antivirus" nocase ascii wide
                        $string18_nimplant_offensive_tool_keyword = "chvancooten/nimbuild" nocase ascii wide
                        $string19_nimplant_offensive_tool_keyword = "chvancooten/NimPlant" nocase ascii wide
                        $string20_nimplant_offensive_tool_keyword = /Cmd\-Execute\-Assembly\./ nocase ascii wide
                        $string21_nimplant_offensive_tool_keyword = /Cmd\-Inline\-Execute\./ nocase ascii wide
                        $string22_nimplant_offensive_tool_keyword = /Cmd\-Shinject\./ nocase ascii wide
                        $string23_nimplant_offensive_tool_keyword = /Cmd\-Upload\./ nocase ascii wide
                        $string24_nimplant_offensive_tool_keyword = "compile_implant" nocase ascii wide
                        $string25_nimplant_offensive_tool_keyword = "ConvertToShellcode" nocase ascii wide
                        $string26_nimplant_offensive_tool_keyword = "dbGetNimplant" nocase ascii wide
                        $string27_nimplant_offensive_tool_keyword = /details\-c80a6994018b23dc\.js/ nocase ascii wide
                        $string28_nimplant_offensive_tool_keyword = "EiD5PDowAAAAEFRQVBSUVZIMdJlSItSYEiLUhhIi1IgSItyUEgPt0pKTTHJSDHArDxhfAIsIEHByQ1BAcHi7VJBUUiLUiCLQj" nocase ascii wide
                        $string29_nimplant_offensive_tool_keyword = "execute-assembly " nocase ascii wide
                        $string30_nimplant_offensive_tool_keyword = /executeAssembly\.nim/ nocase ascii wide
                        $string31_nimplant_offensive_tool_keyword = /f4081a8e30f75d46\.js/ nocase ascii wide
                        $string32_nimplant_offensive_tool_keyword = /fde1b109f9704ff7\.css/ nocase ascii wide
                        $string33_nimplant_offensive_tool_keyword = "getNimplantByGuid" nocase ascii wide
                        $string34_nimplant_offensive_tool_keyword = "getPositionImplant" nocase ascii wide
                        $string35_nimplant_offensive_tool_keyword = "import np_server" nocase ascii wide
                        $string36_nimplant_offensive_tool_keyword = /inline\-execute\s.{0,1000}\.o/ nocase ascii wide
                        $string37_nimplant_offensive_tool_keyword = /inlineExecute\.nim/ nocase ascii wide
                        $string38_nimplant_offensive_tool_keyword = "killAllNimplants" nocase ascii wide
                        $string39_nimplant_offensive_tool_keyword = "localhost:31337" nocase ascii wide
                        $string40_nimplant_offensive_tool_keyword = "NimPlant v" nocase ascii wide
                        $string41_nimplant_offensive_tool_keyword = "nimplant-" nocase ascii wide
                        $string42_nimplant_offensive_tool_keyword = /NimPlant.{0,1000}\.tar\.gz/ nocase ascii wide
                        $string43_nimplant_offensive_tool_keyword = /NimPlant.{0,1000}\.zip/ nocase ascii wide
                        $string44_nimplant_offensive_tool_keyword = /nimplant\.db/ nocase ascii wide
                        $string45_nimplant_offensive_tool_keyword = /NimPlant\.dll/ nocase ascii wide
                        $string46_nimplant_offensive_tool_keyword = /NimPlant\.nim/ nocase ascii wide
                        $string47_nimplant_offensive_tool_keyword = /NimPlant\.nimble/ nocase ascii wide
                        $string48_nimplant_offensive_tool_keyword = /NimPlant\.py/ nocase ascii wide
                        $string49_nimplant_offensive_tool_keyword = "nimplantPrint" nocase ascii wide
                        $string50_nimplant_offensive_tool_keyword = /nimplants\-.{0,1000}\.js/ nocase ascii wide
                        $string51_nimplant_offensive_tool_keyword = /nimplants\.html/ nocase ascii wide
                        $string52_nimplant_offensive_tool_keyword = /\-selfdelete\.exe\s\-d\:selfdelete/ nocase ascii wide
                        $string53_nimplant_offensive_tool_keyword = /server\-7566091c4e4a2a24\.js/ nocase ascii wide
                        $string54_nimplant_offensive_tool_keyword = /shell\s\'cmd\.exe\s\/c/ nocase ascii wide
                        $string55_nimplant_offensive_tool_keyword = /ShellcodeRDI\.py/ nocase ascii wide
                        $string56_nimplant_offensive_tool_keyword = "shinject " nocase ascii wide
                        $string57_nimplant_offensive_tool_keyword = /shinject\.nim/ nocase ascii wide
                        $string58_nimplant_offensive_tool_keyword = /util\.nimplant/ nocase ascii wide
                        $string59_nimplant_offensive_tool_keyword = /whoami\.nim/ nocase ascii wide
                        $string60_nimplant_offensive_tool_keyword = /zippy\.nim/ nocase ascii wide

    condition:
        any of them
}