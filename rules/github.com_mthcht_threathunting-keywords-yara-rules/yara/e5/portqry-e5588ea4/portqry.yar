rule PortQry
{
    meta:
        description = "Detection patterns for the tool 'PortQry' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PortQry"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\/PortQry\.exe/ nocase ascii wide
                        $string2 = /\/PortQryV2\.exe/ nocase ascii wide
                        $string3 = /\\PortQry\.exe/ nocase ascii wide
                        $string4 = /\\PortQryV2\.exe/ nocase ascii wide
                        $string5 = /\\PortQryV2\\/ nocase ascii wide
                        $string6 = /\\RunOnce\\wextract_cleanup0/ nocase ascii wide
                        $string7 = "6471c5190a99e3d1f337fcfef1fc410e8d487b66e093f924700e186cbd398dc0" nocase ascii wide
                        $string8 = "PortQry Command Line Port Scanner" nocase ascii wide
                        $string9 = "portqry -local" nocase ascii wide
                        $string10 = "portqry -n " nocase ascii wide
                        $string11 = "portqry -wpid" nocase ascii wide
                        $string12 = "portqry -wport" nocase ascii wide

    condition:
        any of them
}