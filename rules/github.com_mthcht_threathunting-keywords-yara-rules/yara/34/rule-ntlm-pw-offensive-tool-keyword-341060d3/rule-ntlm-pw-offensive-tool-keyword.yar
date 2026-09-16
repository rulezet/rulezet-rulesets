rule rule_ntlm_pw_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ntlm.pw' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ntlm.pw"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ntlm_pw_offensive_tool_keyword = /https\:\/\/ntlm\.pw/ nocase ascii wide

    condition:
        any of them
}