rule rule_BucketLoot_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'BucketLoot' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BucketLoot"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_BucketLoot_offensive_tool_keyword = /\/BucketLoot\.git/ nocase ascii wide
                        $string2_BucketLoot_offensive_tool_keyword = "bucketloot -" nocase ascii wide
                        $string3_BucketLoot_offensive_tool_keyword = "bucketloot https://" nocase ascii wide
                        $string4_BucketLoot_offensive_tool_keyword = /bucketloot\.exe\s\-/ nocase ascii wide
                        $string5_BucketLoot_offensive_tool_keyword = /bucketloot\.exe\shttps\:\/\// nocase ascii wide
                        $string6_BucketLoot_offensive_tool_keyword = "bucketloot-darwin64"
                        $string7_BucketLoot_offensive_tool_keyword = "bucketloot-freebsd64" nocase ascii wide
                        $string8_BucketLoot_offensive_tool_keyword = "BucketLoot-master" nocase ascii wide
                        $string9_BucketLoot_offensive_tool_keyword = "bucketloot-openbsd64" nocase ascii wide
                        $string10_BucketLoot_offensive_tool_keyword = /bucketloot\-windows32\.exe/ nocase ascii wide
                        $string11_BucketLoot_offensive_tool_keyword = /bucketloot\-windows64\.exe/ nocase ascii wide
                        $string12_BucketLoot_offensive_tool_keyword = "redhuntlabs/BucketLoot" nocase ascii wide

    condition:
        any of them
}