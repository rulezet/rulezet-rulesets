rule RouterScan
{
    meta:
        description = "Detection patterns for the tool 'RouterScan' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RouterScan"
        rule_category = "signature_keyword"

    strings:
                        $string1 = /HackTool\.Win32\.RouterScan/ nocase ascii wide
                        $string2 = "HackTool:Win32/RouterScan" nocase ascii wide

    condition:
        any of them
}