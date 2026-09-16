rule localhost_run
{
    meta:
        description = "Detection patterns for the tool 'localhost.run' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "localhost.run"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /http\:\/\/.{0,1000}\.localhost\.run/ nocase ascii wide
                        $string2 = /https\:\/\/.{0,1000}\.localhost\.run/ nocase ascii wide
                        $string3 = /ssh\s.{0,1000}\s\.localhost\.run/ nocase ascii wide
                        $string4 = /ssh\s.{0,1000}\slocalhost\.run/ nocase ascii wide

    condition:
        any of them
}