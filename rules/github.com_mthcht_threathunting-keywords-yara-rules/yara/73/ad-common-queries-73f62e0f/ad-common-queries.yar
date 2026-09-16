rule AD_common_queries
{
    meta:
        description = "Detection patterns for the tool 'AD-common-queries' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AD-common-queries"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\/AD\-common\-queries\.git/ nocase ascii wide
                        $string2 = /ADUsers\-Disabled\.txt/ nocase ascii wide
                        $string3 = /ADUsers\-PasswordNeverExpires\.txt/ nocase ascii wide
                        $string4 = /ADUsers\-PasswordNotRequired\.txt/ nocase ascii wide
                        $string5 = "swarleysez/AD-common-queries" nocase ascii wide

    condition:
        any of them
}