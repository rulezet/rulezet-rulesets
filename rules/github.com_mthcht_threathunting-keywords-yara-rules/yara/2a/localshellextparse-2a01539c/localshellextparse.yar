rule LocalShellExtParse
{
    meta:
        description = "Detection patterns for the tool 'LocalShellExtParse' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LocalShellExtParse"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sLocalShellExtParse\.py/ nocase ascii wide
                        $string2 = /\.py\s\-\-cached\s\-\-ntuser\sNTUSER\.DAT/ nocase ascii wide
                        $string3 = /\.py\s\-\-ntuser\sNTUSER\.DAT\s\-\-usrclass\sUsrClass\.dat/ nocase ascii wide
                        $string4 = /\/LocalShellExtParse\.git/ nocase ascii wide
                        $string5 = /\/LocalShellExtParse\.py/ nocase ascii wide
                        $string6 = /\\LocalShellExtParse\.py/ nocase ascii wide
                        $string7 = /\\LocalShellExtParse\-master/ nocase ascii wide
                        $string8 = "c3a499f047b670e888a41b33749ffc9227b7b0bcc4e9f0882d272918ee3a17d1" nocase ascii wide
                        $string9 = "herrcore/LocalShellExtParse" nocase ascii wide

    condition:
        any of them
}