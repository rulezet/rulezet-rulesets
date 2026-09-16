rule ufile_io
{
    meta:
        description = "Detection patterns for the tool 'ufile.io' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ufile.io"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /https\:\/\/store\-.{0,1000}\.ufile\.io\/v1\/upload\// nocase ascii wide
                        $string2 = /https\:\/\/ufile\.io\// nocase ascii wide
                        $string3 = /https\:\/\/ufile\.io\/v1\/upload\// nocase ascii wide

    condition:
        any of them
}