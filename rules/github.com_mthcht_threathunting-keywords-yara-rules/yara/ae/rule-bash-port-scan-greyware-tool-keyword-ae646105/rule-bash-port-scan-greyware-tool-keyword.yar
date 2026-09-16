rule rule_bash_port_scan_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'bash port scan' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "bash port scan"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_bash_port_scan_greyware_tool_keyword = /for\si\sin\s\{1\.\.65535\}/

    condition:
        any of them
}