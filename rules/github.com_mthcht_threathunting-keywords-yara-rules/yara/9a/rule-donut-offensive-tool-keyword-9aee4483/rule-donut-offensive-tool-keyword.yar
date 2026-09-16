rule rule_donut_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'donut' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "donut"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_donut_offensive_tool_keyword = /\s\-a\s1\s\-f\s.{0,1000}\.dll\s\-p\shttp/ nocase ascii wide
                        $string2_donut_offensive_tool_keyword = " -DDONUT_EXE " nocase ascii wide
                        $string3_donut_offensive_tool_keyword = /\sDisableETW\(/ nocase ascii wide
                        $string4_donut_offensive_tool_keyword = /\sDisableWLDP\(/ nocase ascii wide
                        $string5_donut_offensive_tool_keyword = /\sdonut\.c\s/ nocase ascii wide
                        $string6_donut_offensive_tool_keyword = /\sdonut\.exe\s/ nocase ascii wide
                        $string7_donut_offensive_tool_keyword = /\sdonut\.o\s/ nocase ascii wide
                        $string8_donut_offensive_tool_keyword = /\s\-u\shttp.{0,1000}\s\-f\s.{0,1000}\.dll\s.{0,1000}\s\-p\s/ nocase ascii wide
                        $string9_donut_offensive_tool_keyword = /\/donut\s.{0,1000}\.exe/
                        $string10_donut_offensive_tool_keyword = /\/donut\.exe/ nocase ascii wide
                        $string11_donut_offensive_tool_keyword = /\/donut\.git/ nocase ascii wide
                        $string12_donut_offensive_tool_keyword = /\/donutmodule\.c/ nocase ascii wide
                        $string13_donut_offensive_tool_keyword = "/DonutTest/" nocase ascii wide
                        $string14_donut_offensive_tool_keyword = /\/loader\/bypass\.c/ nocase ascii wide
                        $string15_donut_offensive_tool_keyword = /\/loader\/bypass\.h/ nocase ascii wide
                        $string16_donut_offensive_tool_keyword = /\\donut\.exe/ nocase ascii wide
                        $string17_donut_offensive_tool_keyword = /DisableAMSI\(/ nocase ascii wide
                        $string18_donut_offensive_tool_keyword = /docker.{0,1000}\sdonut\s/ nocase ascii wide
                        $string19_donut_offensive_tool_keyword = /donut.{0,1000}\s\\DemoCreateProcess\.dll\s/ nocase ascii wide
                        $string20_donut_offensive_tool_keyword = /donut\.exe\s.{0,1000}\.exe/ nocase ascii wide
                        $string21_donut_offensive_tool_keyword = "DONUT_BYPASS_CONTINUE" nocase ascii wide
                        $string22_donut_offensive_tool_keyword = /DonutLoader\(/ nocase ascii wide
                        $string23_donut_offensive_tool_keyword = /donut\-payload\./ nocase ascii wide
                        $string24_donut_offensive_tool_keyword = "donut-shellcode" nocase ascii wide
                        $string25_donut_offensive_tool_keyword = /go\-donut\/.{0,1000}\.exe/ nocase ascii wide
                        $string26_donut_offensive_tool_keyword = /go\-donut\/.{0,1000}\.go/ nocase ascii wide
                        $string27_donut_offensive_tool_keyword = /loader\/inject\.c/ nocase ascii wide
                        $string28_donut_offensive_tool_keyword = /loader\/inject_local\.c/ nocase ascii wide
                        $string29_donut_offensive_tool_keyword = /loader_exe_x64\./ nocase ascii wide
                        $string30_donut_offensive_tool_keyword = /loader_exe_x86\./ nocase ascii wide
                        $string31_donut_offensive_tool_keyword = "nmake inject_local " nocase ascii wide
                        $string32_donut_offensive_tool_keyword = "PDONUT_INSTANCE" nocase ascii wide
                        $string33_donut_offensive_tool_keyword = /ProcessManager\.exe\s\-\-machine\s/ nocase ascii wide
                        $string34_donut_offensive_tool_keyword = /ProcessManager\.exe\s\-\-name\sexplorer/ nocase ascii wide
                        $string35_donut_offensive_tool_keyword = /therealwover\@protonmail\.com/ nocase ascii wide
                        $string36_donut_offensive_tool_keyword = "thewover/donut" nocase ascii wide

    condition:
        any of them
}