rule rule_avred_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'avred' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "avred"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_avred_offensive_tool_keyword = /\savred\.py\s/ nocase ascii wide
                        $string2_avred_offensive_tool_keyword = /\savredweb\.py\s/ nocase ascii wide
                        $string3_avred_offensive_tool_keyword = /\.py\s\-\-file\s.{0,1000}\.ps1\s\-\-server\samsi/ nocase ascii wide
                        $string4_avred_offensive_tool_keyword = /\.py\s\-\-server\samsi\s\-\-file\s.{0,1000}\.exe/ nocase ascii wide
                        $string5_avred_offensive_tool_keyword = /\/avred\.git/ nocase ascii wide
                        $string6_avred_offensive_tool_keyword = /\/avred\.py/ nocase ascii wide
                        $string7_avred_offensive_tool_keyword = /\/avredweb\.py\s/ nocase ascii wide
                        $string8_avred_offensive_tool_keyword = "/dobin/avred" nocase ascii wide
                        $string9_avred_offensive_tool_keyword = /\\avred\.py/ nocase ascii wide
                        $string10_avred_offensive_tool_keyword = /\\avredweb\.py\s/ nocase ascii wide
                        $string11_avred_offensive_tool_keyword = /avred\-main\.zip/ nocase ascii wide
                        $string12_avred_offensive_tool_keyword = /https\:\/\/avred\.r00ted\.ch\/upload/ nocase ascii wide
                        $string13_avred_offensive_tool_keyword = /podman\srun\s.{0,1000}\s\-\-name\savred\s\-d\savred/ nocase ascii wide

    condition:
        any of them
}