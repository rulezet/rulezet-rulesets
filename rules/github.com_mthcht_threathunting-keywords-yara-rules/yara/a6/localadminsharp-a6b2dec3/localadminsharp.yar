rule LocalAdminSharp
{
    meta:
        description = "Detection patterns for the tool 'LocalAdminSharp' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LocalAdminSharp"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "\"localadmin123!\"" nocase ascii wide
                        $string2 = /\/LocalAdminSharp\.git/ nocase ascii wide
                        $string3 = /\/LocalAdminSharp\.sln/ nocase ascii wide
                        $string4 = /\\LocalAdminSharp\.sln/ nocase ascii wide
                        $string5 = "07628592-5A22-4C0A-9330-6C90BD7A94B6" nocase ascii wide
                        $string6 = /LocalAdminSharp\.csproj/ nocase ascii wide
                        $string7 = /LocalAdminSharp\.exe/ nocase ascii wide
                        $string8 = /LocalAdminSharp\-main.{0,1000}\'/ nocase ascii wide
                        $string9 = "notdodo/LocalAdminSharp" nocase ascii wide

    condition:
        any of them
}