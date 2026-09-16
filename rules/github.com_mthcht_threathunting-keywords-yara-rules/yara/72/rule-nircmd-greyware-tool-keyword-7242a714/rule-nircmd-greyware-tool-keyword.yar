rule rule_nircmd_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'nircmd' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nircmd"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_nircmd_greyware_tool_keyword = /\snircmd\.exe/ nocase ascii wide
                        $string2_nircmd_greyware_tool_keyword = /\snircmdc\.exe/ nocase ascii wide
                        $string3_nircmd_greyware_tool_keyword = /\/nircmd\.exe/ nocase ascii wide
                        $string4_nircmd_greyware_tool_keyword = /\/nircmd\.zip/ nocase ascii wide
                        $string5_nircmd_greyware_tool_keyword = /\/nircmdc\.exe/ nocase ascii wide
                        $string6_nircmd_greyware_tool_keyword = /\/nircmd\-x64\.zip/ nocase ascii wide
                        $string7_nircmd_greyware_tool_keyword = /\\nircmd\.exe/ nocase ascii wide
                        $string8_nircmd_greyware_tool_keyword = /\\nircmd\.zip/ nocase ascii wide
                        $string9_nircmd_greyware_tool_keyword = /\\nircmdc\.exe/ nocase ascii wide
                        $string10_nircmd_greyware_tool_keyword = /\\nircmd\-x64\.zip/ nocase ascii wide
                        $string11_nircmd_greyware_tool_keyword = /nircmd\.exe\s/ nocase ascii wide
                        $string12_nircmd_greyware_tool_keyword = /nircmdc\.exe\s/ nocase ascii wide

    condition:
        any of them
}