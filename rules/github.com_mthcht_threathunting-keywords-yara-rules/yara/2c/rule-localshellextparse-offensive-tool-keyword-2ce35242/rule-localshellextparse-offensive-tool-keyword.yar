rule rule_LocalShellExtParse_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'LocalShellExtParse' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LocalShellExtParse"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_LocalShellExtParse_offensive_tool_keyword = /\sLocalShellExtParse\.py/ nocase ascii wide
                        $string2_LocalShellExtParse_offensive_tool_keyword = /\.py\s\-\-cached\s\-\-ntuser\sNTUSER\.DAT/ nocase ascii wide
                        $string3_LocalShellExtParse_offensive_tool_keyword = /\.py\s\-\-ntuser\sNTUSER\.DAT\s\-\-usrclass\sUsrClass\.dat/ nocase ascii wide
                        $string4_LocalShellExtParse_offensive_tool_keyword = /\/LocalShellExtParse\.git/ nocase ascii wide
                        $string5_LocalShellExtParse_offensive_tool_keyword = /\/LocalShellExtParse\.py/ nocase ascii wide
                        $string6_LocalShellExtParse_offensive_tool_keyword = /\\LocalShellExtParse\.py/ nocase ascii wide
                        $string7_LocalShellExtParse_offensive_tool_keyword = /\\LocalShellExtParse\-master/ nocase ascii wide
                        $string8_LocalShellExtParse_offensive_tool_keyword = "c3a499f047b670e888a41b33749ffc9227b7b0bcc4e9f0882d272918ee3a17d1" nocase ascii wide
                        $string9_LocalShellExtParse_offensive_tool_keyword = "herrcore/LocalShellExtParse" nocase ascii wide

    condition:
        any of them
}