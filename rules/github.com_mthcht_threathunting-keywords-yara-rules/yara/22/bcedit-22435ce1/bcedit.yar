rule bcedit
{
    meta:
        description = "Detection patterns for the tool 'bcedit' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "bcedit"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /FOR\s\/F\s\\"tokens\=1\,2.{0,1000}\\"\s\%\%V\sIN\s\(\'bcdedit\'\)\sDO\sSET\sadminTest\=\%\%V/ nocase ascii wide

    condition:
        any of them
}