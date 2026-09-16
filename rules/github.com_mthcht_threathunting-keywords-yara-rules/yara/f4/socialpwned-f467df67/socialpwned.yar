rule SocialPwned
{
    meta:
        description = "Detection patterns for the tool 'SocialPwned' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SocialPwned"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/lib/GHunt/" nocase ascii wide
                        $string2 = /\/PwnDB\.py/ nocase ascii wide
                        $string3 = "/SocialPwned" nocase ascii wide
                        $string4 = /SocialPwned\.git/ nocase ascii wide
                        $string5 = /socialpwned\.py/ nocase ascii wide
                        $string6 = /socialpwned_.{0,1000}\.txt/ nocase ascii wide
                        $string7 = /\-\-tor\-proxy.{0,1000}\-\-pwndb/ nocase ascii wide

    condition:
        any of them
}