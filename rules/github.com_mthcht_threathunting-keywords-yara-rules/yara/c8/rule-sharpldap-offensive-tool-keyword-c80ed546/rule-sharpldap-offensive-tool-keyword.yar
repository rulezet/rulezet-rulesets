rule rule_SharpLDAP_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpLDAP' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpLDAP"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SharpLDAP_offensive_tool_keyword = /\/SharpLDAP\.git/ nocase ascii wide
                        $string2_SharpLDAP_offensive_tool_keyword = /\\SharpLDAP\\/ nocase ascii wide
                        $string3_SharpLDAP_offensive_tool_keyword = "01d38f94612e1b04e52b08c8ab75d8c614a5e9a716b01754ef4884a06e9669c3" nocase ascii wide
                        $string4_SharpLDAP_offensive_tool_keyword = "5afab0c6f13f93b77c833816fd067007f9a0770ff0ce5096b55635fa3d9b96b4" nocase ascii wide
                        $string5_SharpLDAP_offensive_tool_keyword = "90F6244A-5EEE-4A7A-8C75-FA6A52DF34D3" nocase ascii wide
                        $string6_SharpLDAP_offensive_tool_keyword = "mertdas/SharpLDAP" nocase ascii wide
                        $string7_SharpLDAP_offensive_tool_keyword = /SharpLDAP\.csproj/ nocase ascii wide
                        $string8_SharpLDAP_offensive_tool_keyword = /SharpLDAP\.exe/ nocase ascii wide
                        $string9_SharpLDAP_offensive_tool_keyword = /SharpLDAP\.sln/ nocase ascii wide
                        $string10_SharpLDAP_offensive_tool_keyword = "SharpLDAP-main" nocase ascii wide

    condition:
        any of them
}