rule rule_PortQry_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'PortQry' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PortQry"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_PortQry_greyware_tool_keyword = /\/PortQry\.exe/ nocase ascii wide
                        $string2_PortQry_greyware_tool_keyword = /\/PortQryV2\.exe/ nocase ascii wide
                        $string3_PortQry_greyware_tool_keyword = /\\PortQry\.exe/ nocase ascii wide
                        $string4_PortQry_greyware_tool_keyword = /\\PortQryV2\.exe/ nocase ascii wide
                        $string5_PortQry_greyware_tool_keyword = /\\PortQryV2\\/ nocase ascii wide
                        $string6_PortQry_greyware_tool_keyword = /\\RunOnce\\wextract_cleanup0/ nocase ascii wide
                        $string7_PortQry_greyware_tool_keyword = "6471c5190a99e3d1f337fcfef1fc410e8d487b66e093f924700e186cbd398dc0" nocase ascii wide
                        $string8_PortQry_greyware_tool_keyword = "PortQry Command Line Port Scanner" nocase ascii wide
                        $string9_PortQry_greyware_tool_keyword = "portqry -local" nocase ascii wide
                        $string10_PortQry_greyware_tool_keyword = "portqry -n " nocase ascii wide
                        $string11_PortQry_greyware_tool_keyword = "portqry -wpid" nocase ascii wide
                        $string12_PortQry_greyware_tool_keyword = "portqry -wport" nocase ascii wide

    condition:
        any of them
}