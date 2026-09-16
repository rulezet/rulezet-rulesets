rule avred
{
    meta:
        description = "Detection patterns for the tool 'avred' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "avred"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\savred\.py\s/ nocase ascii wide
                        $string2 = /\savredweb\.py\s/ nocase ascii wide
                        $string3 = /\.py\s\-\-file\s.{0,1000}\.ps1\s\-\-server\samsi/ nocase ascii wide
                        $string4 = /\.py\s\-\-server\samsi\s\-\-file\s.{0,1000}\.exe/ nocase ascii wide
                        $string5 = /\/avred\.git/ nocase ascii wide
                        $string6 = /\/avred\.py/ nocase ascii wide
                        $string7 = /\/avredweb\.py\s/ nocase ascii wide
                        $string8 = "/dobin/avred" nocase ascii wide
                        $string9 = /\\avred\.py/ nocase ascii wide
                        $string10 = /\\avredweb\.py\s/ nocase ascii wide
                        $string11 = /avred\-main\.zip/ nocase ascii wide
                        $string12 = /https\:\/\/avred\.r00ted\.ch\/upload/ nocase ascii wide
                        $string13 = /podman\srun\s.{0,1000}\s\-\-name\savred\s\-d\savred/ nocase ascii wide

    condition:
        any of them
}