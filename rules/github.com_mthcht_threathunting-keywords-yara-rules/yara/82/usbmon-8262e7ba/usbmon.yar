rule usbmon
{
    meta:
        description = "Detection patterns for the tool 'usbmon' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "usbmon"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\\usbmon\.txt/

    condition:
        any of them
}