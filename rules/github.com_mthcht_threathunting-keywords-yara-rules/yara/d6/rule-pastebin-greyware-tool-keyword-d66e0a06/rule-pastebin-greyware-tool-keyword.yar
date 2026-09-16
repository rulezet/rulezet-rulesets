rule rule_pastebin_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'pastebin' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pastebin"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_pastebin_greyware_tool_keyword = /pastebin\.com.{0,1000}\/raw\/.{0,1000}\s/ nocase ascii wide
                        $string2_pastebin_greyware_tool_keyword = /pastebin\.com.{0,1000}\/rw\// nocase ascii wide
                        $string3_pastebin_greyware_tool_keyword = /pastebin\.com.{0,1000}api\/api_post\.php/ nocase ascii wide

    condition:
        any of them
}