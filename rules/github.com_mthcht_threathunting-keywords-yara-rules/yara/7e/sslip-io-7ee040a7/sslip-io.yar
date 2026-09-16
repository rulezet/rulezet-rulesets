rule sslip_io
{
    meta:
        description = "Detection patterns for the tool 'sslip.io' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sslip.io"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /http.{0,1000}\.sslip\.io/ nocase ascii wide

    condition:
        any of them
}