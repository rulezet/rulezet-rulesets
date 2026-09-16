rule rule_SocialPwned_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SocialPwned' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SocialPwned"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SocialPwned_offensive_tool_keyword = "/lib/GHunt/" nocase ascii wide
                        $string2_SocialPwned_offensive_tool_keyword = /\/PwnDB\.py/ nocase ascii wide
                        $string3_SocialPwned_offensive_tool_keyword = "/SocialPwned" nocase ascii wide
                        $string4_SocialPwned_offensive_tool_keyword = /SocialPwned\.git/ nocase ascii wide
                        $string5_SocialPwned_offensive_tool_keyword = /socialpwned\.py/ nocase ascii wide
                        $string6_SocialPwned_offensive_tool_keyword = /socialpwned_.{0,1000}\.txt/ nocase ascii wide
                        $string7_SocialPwned_offensive_tool_keyword = /\-\-tor\-proxy.{0,1000}\-\-pwndb/ nocase ascii wide

    condition:
        any of them
}