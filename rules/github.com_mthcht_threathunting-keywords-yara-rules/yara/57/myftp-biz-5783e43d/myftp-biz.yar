rule myftp_biz
{
    meta:
        description = "Detection patterns for the tool 'myftp.biz' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "myftp.biz"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\.myftp\.biz/ nocase ascii wide

    condition:
        any of them
}