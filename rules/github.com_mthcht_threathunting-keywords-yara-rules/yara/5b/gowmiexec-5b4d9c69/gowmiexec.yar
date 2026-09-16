rule goWMIExec
{
    meta:
        description = "Detection patterns for the tool 'goWMIExec' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "goWMIExec"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " goWMIExec_linux_"
                        $string2 = " goWMIExec_mac_" nocase ascii wide
                        $string3 = " goWMIExec_win_" nocase ascii wide
                        $string4 = /\/goWMIExec\.git/ nocase ascii wide
                        $string5 = "/goWMIExec_linux_"
                        $string6 = "/goWMIExec_mac_" nocase ascii wide
                        $string7 = "/goWMIExec_win_" nocase ascii wide
                        $string8 = /\\goWMIExec_linux_/ nocase ascii wide
                        $string9 = /\\goWMIExec_mac_/ nocase ascii wide
                        $string10 = /\\goWMIExec_win_/ nocase ascii wide
                        $string11 = "0e5ae252e2597d44f6e8def9fcdd3562954130a0261776e083959d067795c450" nocase ascii wide
                        $string12 = "5c5dc6546877d616c4479df133654a0fbccc71d5279aa63f2ca560a5abfea31d" nocase ascii wide
                        $string13 = "5cdce3c908a8a7a336d21543c1133071b6395e26ca882cafc05fb6dbdce075f1" nocase ascii wide
                        $string14 = "C-Sto/goWMIExec" nocase ascii wide
                        $string15 = "ef881142422dd10c7ad27424ce2407312b3886c5ee940a4be17153caed6ccaff" nocase ascii wide
                        $string16 = "goWMIExec -target " nocase ascii wide
                        $string17 = "goWMIExec/pkg" nocase ascii wide
                        $string18 = /wmiexec\\wmiexec\.go/ nocase ascii wide

    condition:
        any of them
}