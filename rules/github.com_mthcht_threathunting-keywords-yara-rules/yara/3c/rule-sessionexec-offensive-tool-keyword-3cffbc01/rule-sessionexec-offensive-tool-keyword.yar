rule rule_SessionExec_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SessionExec' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SessionExec"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SessionExec_offensive_tool_keyword = /\/SessionExec\.exe/ nocase ascii wide
                        $string2_SessionExec_offensive_tool_keyword = /\\SessionExec\.exe/ nocase ascii wide
                        $string3_SessionExec_offensive_tool_keyword = "9065655de782c08c41aa0fe11503e92e455fdf4b1a590101221aeb73f8db98e9" nocase ascii wide
                        $string4_SessionExec_offensive_tool_keyword = "function Invoke-SessionExec" nocase ascii wide
                        $string5_SessionExec_offensive_tool_keyword = "Invoke-SessionExec " nocase ascii wide
                        $string6_SessionExec_offensive_tool_keyword = /Invoke\-SessionExec\.ps1/ nocase ascii wide

    condition:
        any of them
}