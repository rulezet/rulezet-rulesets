rule rule_SharpAppLocker_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpAppLocker' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpAppLocker"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SharpAppLocker_offensive_tool_keyword = " by Flangvik & Jean_Maes_1994" nocase ascii wide
                        $string2_SharpAppLocker_offensive_tool_keyword = /\.exe\s\-\-effective\s\-\-allow\s\-\-outfile\s\\"C\:\\Windows\\Tasks\\Rules\.json\\"/ nocase ascii wide
                        $string3_SharpAppLocker_offensive_tool_keyword = /\.exe\s\-\-effective\s\-\-allow\s\-\-rules\=\\"FileHashRule\,FilePathRule\\"\s\-\-outfile\=/ nocase ascii wide
                        $string4_SharpAppLocker_offensive_tool_keyword = /\/SharpAppLocker\.git/ nocase ascii wide
                        $string5_SharpAppLocker_offensive_tool_keyword = /\\SharpAppLocker\./ nocase ascii wide
                        $string6_SharpAppLocker_offensive_tool_keyword = "d43fc4c6e67a332b6abbb4b35186e9a20fa962c6aa4521f49b19f5bf372262d2" nocase ascii wide
                        $string7_SharpAppLocker_offensive_tool_keyword = "f8e1e243c0648d5bfcd2bb529571b4506f26897574537cffbf1399a171746713" nocase ascii wide
                        $string8_SharpAppLocker_offensive_tool_keyword = "FE102D27-DEC4-42E2-BF69-86C79E08B67D" nocase ascii wide
                        $string9_SharpAppLocker_offensive_tool_keyword = "Flangvik/SharpAppLocker" nocase ascii wide
                        $string10_SharpAppLocker_offensive_tool_keyword = /SharpAppLocker\.exe/ nocase ascii wide

    condition:
        any of them
}