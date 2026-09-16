rule rule_HardHatC2_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'HardHatC2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "HardHatC2"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_HardHatC2_offensive_tool_keyword = "/Donut_Linux"
                        $string2_HardHatC2_offensive_tool_keyword = "/Donut_Windows" nocase ascii wide
                        $string3_HardHatC2_offensive_tool_keyword = "196B8469-F798-4ECC-9A77-C1CAB5BF6EAE" nocase ascii wide
                        $string4_HardHatC2_offensive_tool_keyword = "5010BEE8-0944-4655-987F-AB3BB376E774" nocase ascii wide
                        $string5_HardHatC2_offensive_tool_keyword = "62B6EF3C-3180-4730-A2CE-82D27C43A5B2" nocase ascii wide
                        $string6_HardHatC2_offensive_tool_keyword = "920D97B7-8091-4224-8CF7-D9D72A64A7FE" nocase ascii wide
                        $string7_HardHatC2_offensive_tool_keyword = "B1865FC0-5605-4587-9FCB-8B9DF6B5C6B1" nocase ascii wide
                        $string8_HardHatC2_offensive_tool_keyword = /C2TaskMessage\./ nocase ascii wide
                        $string9_HardHatC2_offensive_tool_keyword = /Confuser\.CLI\.Exe/ nocase ascii wide
                        $string10_HardHatC2_offensive_tool_keyword = /CreateC2Dialog\./ nocase ascii wide
                        $string11_HardHatC2_offensive_tool_keyword = /EditC2Dialog\./ nocase ascii wide
                        $string12_HardHatC2_offensive_tool_keyword = /EncodeShellcode\(/ nocase ascii wide
                        $string13_HardHatC2_offensive_tool_keyword = /Engineer_super\.exe/ nocase ascii wide
                        $string14_HardHatC2_offensive_tool_keyword = "HardHatC2" nocase ascii wide
                        $string15_HardHatC2_offensive_tool_keyword = /hardhatc2\.com/ nocase ascii wide
                        $string16_HardHatC2_offensive_tool_keyword = "HardHatC2Client" nocase ascii wide
                        $string17_HardHatC2_offensive_tool_keyword = /http.{0,1000}127\.0\.0\.1\:21802/ nocase ascii wide
                        $string18_HardHatC2_offensive_tool_keyword = /http.{0,1000}127\.0\.0\.1\:5000/ nocase ascii wide
                        $string19_HardHatC2_offensive_tool_keyword = /http.{0,1000}127\.0\.0\.1\:5096/ nocase ascii wide
                        $string20_HardHatC2_offensive_tool_keyword = /http.{0,1000}127\.0\.0\.1\:7096/ nocase ascii wide
                        $string21_HardHatC2_offensive_tool_keyword = /http.{0,1000}127\.0\.0\.1\:8080\/.{0,1000}\.dll/ nocase ascii wide
                        $string22_HardHatC2_offensive_tool_keyword = /http.{0,1000}127\.0\.0\.1\:8080\/.{0,1000}\.exe/ nocase ascii wide
                        $string23_HardHatC2_offensive_tool_keyword = /http.{0,1000}127\.0\.0\.1\:8080\/.{0,1000}\.ps1/ nocase ascii wide
                        $string24_HardHatC2_offensive_tool_keyword = /http.{0,1000}127\.0\.0\.1\:9631/ nocase ascii wide
                        $string25_HardHatC2_offensive_tool_keyword = /http.{0,1000}localhost\:21802/ nocase ascii wide
                        $string26_HardHatC2_offensive_tool_keyword = /http.{0,1000}localhost\:5000/ nocase ascii wide
                        $string27_HardHatC2_offensive_tool_keyword = /http.{0,1000}localhost\:5096/ nocase ascii wide
                        $string28_HardHatC2_offensive_tool_keyword = /http.{0,1000}localhost\:7096/ nocase ascii wide
                        $string29_HardHatC2_offensive_tool_keyword = /http.{0,1000}localhost\:9631/ nocase ascii wide
                        $string30_HardHatC2_offensive_tool_keyword = /inlineAssembly.{0,1000}\/execmethod/ nocase ascii wide
                        $string31_HardHatC2_offensive_tool_keyword = /inlineDll.{0,1000}\/dll/ nocase ascii wide
                        $string32_HardHatC2_offensive_tool_keyword = "InlineShellcode" nocase ascii wide
                        $string33_HardHatC2_offensive_tool_keyword = "jtee43gt-6543-2iur-9422-83r5w27hgzaq" nocase ascii wide
                        $string34_HardHatC2_offensive_tool_keyword = /Patch\-AMSI\./ nocase ascii wide
                        $string35_HardHatC2_offensive_tool_keyword = /Patch\-ETW\./ nocase ascii wide
                        $string36_HardHatC2_offensive_tool_keyword = /powerkatz\.dll/ nocase ascii wide
                        $string37_HardHatC2_offensive_tool_keyword = /spawnto\s.{0,1000}\/path\s/ nocase ascii wide
                        $string38_HardHatC2_offensive_tool_keyword = /unmanagedPowershell\s.{0,1000}\/command/ nocase ascii wide

    condition:
        any of them
}