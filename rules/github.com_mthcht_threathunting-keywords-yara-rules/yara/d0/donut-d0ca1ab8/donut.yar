rule donut
{
    meta:
        description = "Detection patterns for the tool 'donut' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "donut"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\-a\s1\s\-f\s.{0,1000}\.dll\s\-p\shttp/ nocase ascii wide
                        $string2 = " -DDONUT_EXE " nocase ascii wide
                        $string3 = /\sDisableETW\(/ nocase ascii wide
                        $string4 = /\sDisableWLDP\(/ nocase ascii wide
                        $string5 = /\sdonut\.c\s/ nocase ascii wide
                        $string6 = /\sdonut\.exe\s/ nocase ascii wide
                        $string7 = /\sdonut\.o\s/ nocase ascii wide
                        $string8 = /\s\-u\shttp.{0,1000}\s\-f\s.{0,1000}\.dll\s.{0,1000}\s\-p\s/ nocase ascii wide
                        $string9 = /\/donut\s.{0,1000}\.exe/
                        $string10 = /\/donut\.exe/ nocase ascii wide
                        $string11 = /\/donut\.git/ nocase ascii wide
                        $string12 = /\/donutmodule\.c/ nocase ascii wide
                        $string13 = "/DonutTest/" nocase ascii wide
                        $string14 = /\/loader\/bypass\.c/ nocase ascii wide
                        $string15 = /\/loader\/bypass\.h/ nocase ascii wide
                        $string16 = /\\donut\.exe/ nocase ascii wide
                        $string17 = /DisableAMSI\(/ nocase ascii wide
                        $string18 = /docker.{0,1000}\sdonut\s/ nocase ascii wide
                        $string19 = /donut.{0,1000}\s\\DemoCreateProcess\.dll\s/ nocase ascii wide
                        $string20 = /donut\.exe\s.{0,1000}\.exe/ nocase ascii wide
                        $string21 = "DONUT_BYPASS_CONTINUE" nocase ascii wide
                        $string22 = /DonutLoader\(/ nocase ascii wide
                        $string23 = /donut\-payload\./ nocase ascii wide
                        $string24 = "donut-shellcode" nocase ascii wide
                        $string25 = /go\-donut\/.{0,1000}\.exe/ nocase ascii wide
                        $string26 = /go\-donut\/.{0,1000}\.go/ nocase ascii wide
                        $string27 = /loader\/inject\.c/ nocase ascii wide
                        $string28 = /loader\/inject_local\.c/ nocase ascii wide
                        $string29 = /loader_exe_x64\./ nocase ascii wide
                        $string30 = /loader_exe_x86\./ nocase ascii wide
                        $string31 = "nmake inject_local " nocase ascii wide
                        $string32 = "PDONUT_INSTANCE" nocase ascii wide
                        $string33 = /ProcessManager\.exe\s\-\-machine\s/ nocase ascii wide
                        $string34 = /ProcessManager\.exe\s\-\-name\sexplorer/ nocase ascii wide
                        $string35 = /therealwover\@protonmail\.com/ nocase ascii wide
                        $string36 = "thewover/donut" nocase ascii wide

    condition:
        any of them
}