rule GCPBucketBrute
{
    meta:
        description = "Detection patterns for the tool 'GCPBucketBrute' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GCPBucketBrute"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "GCPBucketBrute" nocase ascii wide

    condition:
        any of them
}