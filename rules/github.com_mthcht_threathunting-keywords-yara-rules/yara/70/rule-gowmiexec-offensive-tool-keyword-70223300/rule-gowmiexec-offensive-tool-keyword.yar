rule rule_goWMIExec_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'goWMIExec' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "goWMIExec"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_goWMIExec_offensive_tool_keyword = " goWMIExec_linux_"
                        $string2_goWMIExec_offensive_tool_keyword = " goWMIExec_mac_" nocase ascii wide
                        $string3_goWMIExec_offensive_tool_keyword = " goWMIExec_win_" nocase ascii wide
                        $string4_goWMIExec_offensive_tool_keyword = /\/goWMIExec\.git/ nocase ascii wide
                        $string5_goWMIExec_offensive_tool_keyword = "/goWMIExec_linux_"
                        $string6_goWMIExec_offensive_tool_keyword = "/goWMIExec_mac_" nocase ascii wide
                        $string7_goWMIExec_offensive_tool_keyword = "/goWMIExec_win_" nocase ascii wide
                        $string8_goWMIExec_offensive_tool_keyword = /\\goWMIExec_linux_/ nocase ascii wide
                        $string9_goWMIExec_offensive_tool_keyword = /\\goWMIExec_mac_/ nocase ascii wide
                        $string10_goWMIExec_offensive_tool_keyword = /\\goWMIExec_win_/ nocase ascii wide
                        $string11_goWMIExec_offensive_tool_keyword = "0e5ae252e2597d44f6e8def9fcdd3562954130a0261776e083959d067795c450" nocase ascii wide
                        $string12_goWMIExec_offensive_tool_keyword = "5c5dc6546877d616c4479df133654a0fbccc71d5279aa63f2ca560a5abfea31d" nocase ascii wide
                        $string13_goWMIExec_offensive_tool_keyword = "5cdce3c908a8a7a336d21543c1133071b6395e26ca882cafc05fb6dbdce075f1" nocase ascii wide
                        $string14_goWMIExec_offensive_tool_keyword = "C-Sto/goWMIExec" nocase ascii wide
                        $string15_goWMIExec_offensive_tool_keyword = "ef881142422dd10c7ad27424ce2407312b3886c5ee940a4be17153caed6ccaff" nocase ascii wide
                        $string16_goWMIExec_offensive_tool_keyword = "goWMIExec -target " nocase ascii wide
                        $string17_goWMIExec_offensive_tool_keyword = "goWMIExec/pkg" nocase ascii wide
                        $string18_goWMIExec_offensive_tool_keyword = /wmiexec\\wmiexec\.go/ nocase ascii wide

    condition:
        any of them
}