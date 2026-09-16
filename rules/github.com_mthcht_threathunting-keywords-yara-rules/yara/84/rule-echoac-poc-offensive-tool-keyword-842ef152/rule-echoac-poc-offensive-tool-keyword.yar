rule rule_echoac_poc_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'echoac-poc' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "echoac-poc"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_echoac_poc_offensive_tool_keyword = /\/echoac\-poc\.git/ nocase ascii wide
                        $string2_echoac_poc_offensive_tool_keyword = "/PoC/PrivilegeEscalation" nocase ascii wide
                        $string3_echoac_poc_offensive_tool_keyword = /\\PoC\\PrivilegeEscalation/ nocase ascii wide
                        $string4_echoac_poc_offensive_tool_keyword = "echoac-poc-main" nocase ascii wide
                        $string5_echoac_poc_offensive_tool_keyword = "kite03/echoac-poc" nocase ascii wide
                        $string6_echoac_poc_offensive_tool_keyword = /shell\sshould\snow\sbe\srunning\sas\snt\sauthority\\\\system\!/ nocase ascii wide

    condition:
        any of them
}