rule BucketLoot
{
    meta:
        description = "Detection patterns for the tool 'BucketLoot' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BucketLoot"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/BucketLoot\.git/ nocase ascii wide
                        $string2 = "bucketloot -" nocase ascii wide
                        $string3 = "bucketloot https://" nocase ascii wide
                        $string4 = /bucketloot\.exe\s\-/ nocase ascii wide
                        $string5 = /bucketloot\.exe\shttps\:\/\// nocase ascii wide
                        $string6 = "bucketloot-darwin64"
                        $string7 = "bucketloot-freebsd64" nocase ascii wide
                        $string8 = "BucketLoot-master" nocase ascii wide
                        $string9 = "bucketloot-openbsd64" nocase ascii wide
                        $string10 = /bucketloot\-windows32\.exe/ nocase ascii wide
                        $string11 = /bucketloot\-windows64\.exe/ nocase ascii wide
                        $string12 = "redhuntlabs/BucketLoot" nocase ascii wide

    condition:
        any of them
}