rule rule_SharpSQLPwn_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpSQLPwn' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpSQLPwn"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SharpSQLPwn_offensive_tool_keyword = /\s\/cmdtech\:.{0,1000}\s\/cmd\:.{0,1000}\s\/impuser\:/ nocase ascii wide
                        $string2_SharpSQLPwn_offensive_tool_keyword = /\s\/cmdtech\:.{0,1000}\s\/cmd\:.{0,1000}\s\/query\:/ nocase ascii wide
                        $string3_SharpSQLPwn_offensive_tool_keyword = /\s\/modules\:.{0,1000}\s\/target\:.{0,1000}\s\/linkedsql\:/ nocase ascii wide
                        $string4_SharpSQLPwn_offensive_tool_keyword = "SharpSQLPwn" nocase ascii wide

    condition:
        any of them
}