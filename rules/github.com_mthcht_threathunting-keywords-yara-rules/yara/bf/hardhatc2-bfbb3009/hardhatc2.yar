rule HardHatC2
{
    meta:
        description = "Detection patterns for the tool 'HardHatC2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "HardHatC2"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/Donut_Linux"
                        $string2 = "/Donut_Windows" nocase ascii wide
                        $string3 = "196B8469-F798-4ECC-9A77-C1CAB5BF6EAE" nocase ascii wide
                        $string4 = "5010BEE8-0944-4655-987F-AB3BB376E774" nocase ascii wide
                        $string5 = "62B6EF3C-3180-4730-A2CE-82D27C43A5B2" nocase ascii wide
                        $string6 = "920D97B7-8091-4224-8CF7-D9D72A64A7FE" nocase ascii wide
                        $string7 = "B1865FC0-5605-4587-9FCB-8B9DF6B5C6B1" nocase ascii wide
                        $string8 = /C2TaskMessage\./ nocase ascii wide
                        $string9 = /Confuser\.CLI\.Exe/ nocase ascii wide
                        $string10 = /CreateC2Dialog\./ nocase ascii wide
                        $string11 = /EditC2Dialog\./ nocase ascii wide
                        $string12 = /EncodeShellcode\(/ nocase ascii wide
                        $string13 = /Engineer_super\.exe/ nocase ascii wide
                        $string14 = "HardHatC2" nocase ascii wide
                        $string15 = /hardhatc2\.com/ nocase ascii wide
                        $string16 = "HardHatC2Client" nocase ascii wide
                        $string17 = /http.{0,1000}127\.0\.0\.1\:21802/ nocase ascii wide
                        $string18 = /http.{0,1000}127\.0\.0\.1\:5000/ nocase ascii wide
                        $string19 = /http.{0,1000}127\.0\.0\.1\:5096/ nocase ascii wide
                        $string20 = /http.{0,1000}127\.0\.0\.1\:7096/ nocase ascii wide
                        $string21 = /http.{0,1000}127\.0\.0\.1\:8080\/.{0,1000}\.dll/ nocase ascii wide
                        $string22 = /http.{0,1000}127\.0\.0\.1\:8080\/.{0,1000}\.exe/ nocase ascii wide
                        $string23 = /http.{0,1000}127\.0\.0\.1\:8080\/.{0,1000}\.ps1/ nocase ascii wide
                        $string24 = /http.{0,1000}127\.0\.0\.1\:9631/ nocase ascii wide
                        $string25 = /http.{0,1000}localhost\:21802/ nocase ascii wide
                        $string26 = /http.{0,1000}localhost\:5000/ nocase ascii wide
                        $string27 = /http.{0,1000}localhost\:5096/ nocase ascii wide
                        $string28 = /http.{0,1000}localhost\:7096/ nocase ascii wide
                        $string29 = /http.{0,1000}localhost\:9631/ nocase ascii wide
                        $string30 = /inlineAssembly.{0,1000}\/execmethod/ nocase ascii wide
                        $string31 = /inlineDll.{0,1000}\/dll/ nocase ascii wide
                        $string32 = "InlineShellcode" nocase ascii wide
                        $string33 = "jtee43gt-6543-2iur-9422-83r5w27hgzaq" nocase ascii wide
                        $string34 = /Patch\-AMSI\./ nocase ascii wide
                        $string35 = /Patch\-ETW\./ nocase ascii wide
                        $string36 = /powerkatz\.dll/ nocase ascii wide
                        $string37 = /spawnto\s.{0,1000}\/path\s/ nocase ascii wide
                        $string38 = /unmanagedPowershell\s.{0,1000}\/command/ nocase ascii wide

    condition:
        any of them
}