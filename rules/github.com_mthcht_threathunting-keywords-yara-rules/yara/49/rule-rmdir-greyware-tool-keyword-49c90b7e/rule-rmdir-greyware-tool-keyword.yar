rule rule_rmdir__greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'rmdir ' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "rmdir "
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_rmdir__greyware_tool_keyword = /rd\s\/s\s\/q\s\%systemdrive\%\\\$RECYCLE\.BIN/ nocase ascii wide

    condition:
        any of them
}