rule file_io
{
    meta:
        description = "Detection patterns for the tool 'file.io' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "file.io"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /https\:\/\/file\.io\// nocase ascii wide
                        $string2 = /https\:\/\/file\.io\/\?title\=/ nocase ascii wide

    condition:
        any of them
}