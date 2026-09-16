rule Kubestroyer
{
    meta:
        description = "Detection patterns for the tool 'Kubestroyer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Kubestroyer"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\.\/kubestroyer/
                        $string2 = /\/Kubestroyer\.git/ nocase ascii wide
                        $string3 = "cmd/kubestroyer" nocase ascii wide
                        $string4 = "kubestroyer -t " nocase ascii wide
                        $string5 = "Kubestroyer@latest" nocase ascii wide
                        $string6 = "kubestroyer_linux_x64"
                        $string7 = "kubestroyer_macos_arm64" nocase ascii wide
                        $string8 = "kubestroyer_macos_x64" nocase ascii wide
                        $string9 = "kubestroyer_windows_x64" nocase ascii wide
                        $string10 = "Kubestroyer-master" nocase ascii wide
                        $string11 = "Rolix44/Kubestroyer" nocase ascii wide
                        $string12 = "Starting port scan for " nocase ascii wide
                        $string13 = /Trying\sanon\sRCE\susing\s.{0,1000}\sfor\s/ nocase ascii wide

    condition:
        any of them
}