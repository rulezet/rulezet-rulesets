rule echoac_poc
{
    meta:
        description = "Detection patterns for the tool 'echoac-poc' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "echoac-poc"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/echoac\-poc\.git/ nocase ascii wide
                        $string2 = "/PoC/PrivilegeEscalation" nocase ascii wide
                        $string3 = /\\PoC\\PrivilegeEscalation/ nocase ascii wide
                        $string4 = "echoac-poc-main" nocase ascii wide
                        $string5 = "kite03/echoac-poc" nocase ascii wide
                        $string6 = /shell\sshould\snow\sbe\srunning\sas\snt\sauthority\\\\system\!/ nocase ascii wide

    condition:
        any of them
}