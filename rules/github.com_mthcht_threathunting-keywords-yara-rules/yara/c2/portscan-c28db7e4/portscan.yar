rule portscan
{
    meta:
        description = "Detection patterns for the tool 'portscan' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "portscan"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/portscan\.git/ nocase ascii wide
                        $string2 = "/portscan/releases/" nocase ascii wide
                        $string3 = "57c646df3c07792d9c6e479b7faa5ccd7802dc03dc49e477534e2322cb753bf9" nocase ascii wide
                        $string4 = "zs5460/portscan" nocase ascii wide

    condition:
        any of them
}