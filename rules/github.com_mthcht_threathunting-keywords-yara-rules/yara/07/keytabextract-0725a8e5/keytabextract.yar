rule KeyTabExtract
{
    meta:
        description = "Detection patterns for the tool 'KeyTabExtract' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "KeyTabExtract"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "KeyTabExtract"

    condition:
        any of them
}