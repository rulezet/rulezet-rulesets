rule rule_AD_common_queries_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'AD-common-queries' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AD-common-queries"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_AD_common_queries_greyware_tool_keyword = /\/AD\-common\-queries\.git/ nocase ascii wide
                        $string2_AD_common_queries_greyware_tool_keyword = /ADUsers\-Disabled\.txt/ nocase ascii wide
                        $string3_AD_common_queries_greyware_tool_keyword = /ADUsers\-PasswordNeverExpires\.txt/ nocase ascii wide
                        $string4_AD_common_queries_greyware_tool_keyword = /ADUsers\-PasswordNotRequired\.txt/ nocase ascii wide
                        $string5_AD_common_queries_greyware_tool_keyword = "swarleysez/AD-common-queries" nocase ascii wide

    condition:
        any of them
}