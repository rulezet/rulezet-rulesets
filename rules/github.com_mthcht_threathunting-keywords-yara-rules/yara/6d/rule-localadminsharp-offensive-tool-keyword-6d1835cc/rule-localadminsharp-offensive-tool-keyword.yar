rule rule_LocalAdminSharp_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'LocalAdminSharp' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LocalAdminSharp"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_LocalAdminSharp_offensive_tool_keyword = "\"localadmin123!\"" nocase ascii wide
                        $string2_LocalAdminSharp_offensive_tool_keyword = /\/LocalAdminSharp\.git/ nocase ascii wide
                        $string3_LocalAdminSharp_offensive_tool_keyword = /\/LocalAdminSharp\.sln/ nocase ascii wide
                        $string4_LocalAdminSharp_offensive_tool_keyword = /\\LocalAdminSharp\.sln/ nocase ascii wide
                        $string5_LocalAdminSharp_offensive_tool_keyword = "07628592-5A22-4C0A-9330-6C90BD7A94B6" nocase ascii wide
                        $string6_LocalAdminSharp_offensive_tool_keyword = /LocalAdminSharp\.csproj/ nocase ascii wide
                        $string7_LocalAdminSharp_offensive_tool_keyword = /LocalAdminSharp\.exe/ nocase ascii wide
                        $string8_LocalAdminSharp_offensive_tool_keyword = /LocalAdminSharp\-main.{0,1000}\'/ nocase ascii wide
                        $string9_LocalAdminSharp_offensive_tool_keyword = "notdodo/LocalAdminSharp" nocase ascii wide

    condition:
        any of them
}