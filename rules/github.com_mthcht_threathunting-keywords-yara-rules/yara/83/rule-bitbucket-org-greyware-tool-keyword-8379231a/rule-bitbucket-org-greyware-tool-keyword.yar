rule rule_bitbucket_org_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'bitbucket.org' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "bitbucket.org"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_bitbucket_org_greyware_tool_keyword = /https\:\/\/bitbucket\.org\/.{0,1000}\/downloads\/.{0,1000}\.bat/ nocase ascii wide
                        $string2_bitbucket_org_greyware_tool_keyword = /https\:\/\/bitbucket\.org\/.{0,1000}\/downloads\/.{0,1000}\.dll/ nocase ascii wide
                        $string3_bitbucket_org_greyware_tool_keyword = /https\:\/\/bitbucket\.org\/.{0,1000}\/downloads\/.{0,1000}\.dll/ nocase ascii wide
                        $string4_bitbucket_org_greyware_tool_keyword = /https\:\/\/bitbucket\.org\/.{0,1000}\/downloads\/.{0,1000}\.exe/ nocase ascii wide
                        $string5_bitbucket_org_greyware_tool_keyword = /https\:\/\/bitbucket\.org\/.{0,1000}\/downloads\/.{0,1000}\.ps1/ nocase ascii wide
                        $string6_bitbucket_org_greyware_tool_keyword = /https\:\/\/bitbucket\.org\/.{0,1000}\/downloads\/.{0,1000}\.rar/ nocase ascii wide
                        $string7_bitbucket_org_greyware_tool_keyword = /https\:\/\/bitbucket\.org\/.{0,1000}\/downloads\/.{0,1000}\.zip/ nocase ascii wide

    condition:
        any of them
}