rule pastebin
{
    meta:
        description = "Detection patterns for the tool 'pastebin' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pastebin"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /pastebin\.com.{0,1000}\/raw\/.{0,1000}\s/ nocase ascii wide
                        $string2 = /pastebin\.com.{0,1000}\/rw\// nocase ascii wide
                        $string3 = /pastebin\.com.{0,1000}api\/api_post\.php/ nocase ascii wide

    condition:
        any of them
}