rule rule_Kubestroyer_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Kubestroyer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Kubestroyer"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Kubestroyer_offensive_tool_keyword = /\.\/kubestroyer/
                        $string2_Kubestroyer_offensive_tool_keyword = /\/Kubestroyer\.git/ nocase ascii wide
                        $string3_Kubestroyer_offensive_tool_keyword = "cmd/kubestroyer" nocase ascii wide
                        $string4_Kubestroyer_offensive_tool_keyword = "kubestroyer -t " nocase ascii wide
                        $string5_Kubestroyer_offensive_tool_keyword = "Kubestroyer@latest" nocase ascii wide
                        $string6_Kubestroyer_offensive_tool_keyword = "kubestroyer_linux_x64"
                        $string7_Kubestroyer_offensive_tool_keyword = "kubestroyer_macos_arm64" nocase ascii wide
                        $string8_Kubestroyer_offensive_tool_keyword = "kubestroyer_macos_x64" nocase ascii wide
                        $string9_Kubestroyer_offensive_tool_keyword = "kubestroyer_windows_x64" nocase ascii wide
                        $string10_Kubestroyer_offensive_tool_keyword = "Kubestroyer-master" nocase ascii wide
                        $string11_Kubestroyer_offensive_tool_keyword = "Rolix44/Kubestroyer" nocase ascii wide
                        $string12_Kubestroyer_offensive_tool_keyword = "Starting port scan for " nocase ascii wide
                        $string13_Kubestroyer_offensive_tool_keyword = /Trying\sanon\sRCE\susing\s.{0,1000}\sfor\s/ nocase ascii wide

    condition:
        any of them
}