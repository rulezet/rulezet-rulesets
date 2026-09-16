rule nimplant
{
    meta:
        description = "Detection patterns for the tool 'nimplant' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nimplant"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " -d:sleepmask" nocase ascii wide
                        $string2 = " exe-selfdelete" nocase ascii wide
                        $string3 = " --nomain -d:exportDll --passL:" nocase ascii wide
                        $string4 = /\.nimplant/ nocase ascii wide
                        $string5 = /\.ShellcodeRDI/ nocase ascii wide
                        $string6 = /\/NimPlant\./ nocase ascii wide
                        $string7 = "/NimPlant/" nocase ascii wide
                        $string8 = "/nimplants/" nocase ascii wide
                        $string9 = /\\NimPlant\./ nocase ascii wide
                        $string10 = "_nimplant_" nocase ascii wide
                        $string11 = /127\.0\.0\.1\:31337/ nocase ascii wide
                        $string12 = "789CF3CBCC0DC849CC2B51703652084E2D2A4B2D02003B5C0650" nocase ascii wide
                        $string13 = "BeaconGetSpawnTo" nocase ascii wide
                        $string14 = "BeaconInjectProcess" nocase ascii wide
                        $string15 = "C2 Client" nocase ascii wide
                        $string16 = "C2 Nimplant Server" nocase ascii wide
                        $string17 = "Cannot enumerate antivirus" nocase ascii wide
                        $string18 = "chvancooten/nimbuild" nocase ascii wide
                        $string19 = "chvancooten/NimPlant" nocase ascii wide
                        $string20 = /Cmd\-Execute\-Assembly\./ nocase ascii wide
                        $string21 = /Cmd\-Inline\-Execute\./ nocase ascii wide
                        $string22 = /Cmd\-Shinject\./ nocase ascii wide
                        $string23 = /Cmd\-Upload\./ nocase ascii wide
                        $string24 = "compile_implant" nocase ascii wide
                        $string25 = "ConvertToShellcode" nocase ascii wide
                        $string26 = "dbGetNimplant" nocase ascii wide
                        $string27 = /details\-c80a6994018b23dc\.js/ nocase ascii wide
                        $string28 = "EiD5PDowAAAAEFRQVBSUVZIMdJlSItSYEiLUhhIi1IgSItyUEgPt0pKTTHJSDHArDxhfAIsIEHByQ1BAcHi7VJBUUiLUiCLQj" nocase ascii wide
                        $string29 = "execute-assembly " nocase ascii wide
                        $string30 = /executeAssembly\.nim/ nocase ascii wide
                        $string31 = /f4081a8e30f75d46\.js/ nocase ascii wide
                        $string32 = /fde1b109f9704ff7\.css/ nocase ascii wide
                        $string33 = "getNimplantByGuid" nocase ascii wide
                        $string34 = "getPositionImplant" nocase ascii wide
                        $string35 = "import np_server" nocase ascii wide
                        $string36 = /inline\-execute\s.{0,1000}\.o/ nocase ascii wide
                        $string37 = /inlineExecute\.nim/ nocase ascii wide
                        $string38 = "killAllNimplants" nocase ascii wide
                        $string39 = "localhost:31337" nocase ascii wide
                        $string40 = "NimPlant v" nocase ascii wide
                        $string41 = "nimplant-" nocase ascii wide
                        $string42 = /NimPlant.{0,1000}\.tar\.gz/ nocase ascii wide
                        $string43 = /NimPlant.{0,1000}\.zip/ nocase ascii wide
                        $string44 = /nimplant\.db/ nocase ascii wide
                        $string45 = /NimPlant\.dll/ nocase ascii wide
                        $string46 = /NimPlant\.nim/ nocase ascii wide
                        $string47 = /NimPlant\.nimble/ nocase ascii wide
                        $string48 = /NimPlant\.py/ nocase ascii wide
                        $string49 = "nimplantPrint" nocase ascii wide
                        $string50 = /nimplants\-.{0,1000}\.js/ nocase ascii wide
                        $string51 = /nimplants\.html/ nocase ascii wide
                        $string52 = /\-selfdelete\.exe\s\-d\:selfdelete/ nocase ascii wide
                        $string53 = /server\-7566091c4e4a2a24\.js/ nocase ascii wide
                        $string54 = /shell\s\'cmd\.exe\s\/c/ nocase ascii wide
                        $string55 = /ShellcodeRDI\.py/ nocase ascii wide
                        $string56 = "shinject " nocase ascii wide
                        $string57 = /shinject\.nim/ nocase ascii wide
                        $string58 = /util\.nimplant/ nocase ascii wide
                        $string59 = /whoami\.nim/ nocase ascii wide
                        $string60 = /zippy\.nim/ nocase ascii wide

    condition:
        any of them
}