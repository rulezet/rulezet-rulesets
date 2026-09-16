rule rule_BlankOBF_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'BlankOBF' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BlankOBF"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_BlankOBF_offensive_tool_keyword = /\sBlankOBFv2\.py/ nocase ascii wide
                        $string2_BlankOBF_offensive_tool_keyword = /\/BlankOBF\.git/ nocase ascii wide
                        $string3_BlankOBF_offensive_tool_keyword = /\/BlankOBFv2\.py/ nocase ascii wide
                        $string4_BlankOBF_offensive_tool_keyword = /\\BlankOBFv2\.py/ nocase ascii wide
                        $string5_BlankOBF_offensive_tool_keyword = "bc4657ac480d1f46349254c1d217dba4725fe54bbfa5fe7492c6a1bf1c6afebe" nocase ascii wide
                        $string6_BlankOBF_offensive_tool_keyword = "Blank-c/BlankOBF" nocase ascii wide
                        $string7_BlankOBF_offensive_tool_keyword = "BlankOBF v2: Obfuscates Python code to make it unreadable and hard to reverse" nocase ascii wide
                        $string8_BlankOBF_offensive_tool_keyword = "from BlankOBFv2 import " nocase ascii wide
                        $string9_BlankOBF_offensive_tool_keyword = "You managed to break through BlankOBF v2; Give yourself a pat on your back!" nocase ascii wide

    condition:
        any of them
}