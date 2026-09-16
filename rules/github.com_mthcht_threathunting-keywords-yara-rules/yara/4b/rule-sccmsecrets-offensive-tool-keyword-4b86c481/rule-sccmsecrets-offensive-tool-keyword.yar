rule rule_SCCMSecrets_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SCCMSecrets' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SCCMSecrets"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SCCMSecrets_offensive_tool_keyword = " --bruteforce-range " nocase ascii wide
                        $string2_SCCMSecrets_offensive_tool_keyword = /\/SCCMSecrets\.git/ nocase ascii wide
                        $string3_SCCMSecrets_offensive_tool_keyword = /bruteforcePackageIDs\(/ nocase ascii wide
                        $string4_SCCMSecrets_offensive_tool_keyword = "e3f71f6245226059b306c744af8038d045104c2a12aef8f6b6a254d963927e68" nocase ascii wide
                        $string5_SCCMSecrets_offensive_tool_keyword = /SCCMSecrets\.py/ nocase ascii wide
                        $string6_SCCMSecrets_offensive_tool_keyword = "synacktiv/SCCMSecrets" nocase ascii wide

    condition:
        any of them
}