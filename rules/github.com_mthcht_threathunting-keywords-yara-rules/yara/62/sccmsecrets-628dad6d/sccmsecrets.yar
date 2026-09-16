rule SCCMSecrets
{
    meta:
        description = "Detection patterns for the tool 'SCCMSecrets' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SCCMSecrets"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " --bruteforce-range " nocase ascii wide
                        $string2 = /\/SCCMSecrets\.git/ nocase ascii wide
                        $string3 = /bruteforcePackageIDs\(/ nocase ascii wide
                        $string4 = "e3f71f6245226059b306c744af8038d045104c2a12aef8f6b6a254d963927e68" nocase ascii wide
                        $string5 = /SCCMSecrets\.py/ nocase ascii wide
                        $string6 = "synacktiv/SCCMSecrets" nocase ascii wide

    condition:
        any of them
}