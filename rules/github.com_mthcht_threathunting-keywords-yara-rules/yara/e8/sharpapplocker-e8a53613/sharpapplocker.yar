rule SharpAppLocker
{
    meta:
        description = "Detection patterns for the tool 'SharpAppLocker' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpAppLocker"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " by Flangvik & Jean_Maes_1994" nocase ascii wide
                        $string2 = /\.exe\s\-\-effective\s\-\-allow\s\-\-outfile\s\\"C\:\\Windows\\Tasks\\Rules\.json\\"/ nocase ascii wide
                        $string3 = /\.exe\s\-\-effective\s\-\-allow\s\-\-rules\=\\"FileHashRule\,FilePathRule\\"\s\-\-outfile\=/ nocase ascii wide
                        $string4 = /\/SharpAppLocker\.git/ nocase ascii wide
                        $string5 = /\\SharpAppLocker\./ nocase ascii wide
                        $string6 = "d43fc4c6e67a332b6abbb4b35186e9a20fa962c6aa4521f49b19f5bf372262d2" nocase ascii wide
                        $string7 = "f8e1e243c0648d5bfcd2bb529571b4506f26897574537cffbf1399a171746713" nocase ascii wide
                        $string8 = "FE102D27-DEC4-42E2-BF69-86C79E08B67D" nocase ascii wide
                        $string9 = "Flangvik/SharpAppLocker" nocase ascii wide
                        $string10 = /SharpAppLocker\.exe/ nocase ascii wide

    condition:
        any of them
}