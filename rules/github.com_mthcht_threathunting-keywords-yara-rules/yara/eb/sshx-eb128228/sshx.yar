rule sshx
{
    meta:
        description = "Detection patterns for the tool 'sshx' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sshx"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = " --bin sshx-server" nocase ascii wide
                        $string2 = " s3://sshx/" nocase ascii wide
                        $string3 = /\.vm\.sshx\.internal\:8051/ nocase ascii wide
                        $string4 = "/release/sshx-server" nocase ascii wide
                        $string5 = "/sshx-server/" nocase ascii wide
                        $string6 = /\\sshx\-.{0,1000}\.tar\.gz/ nocase ascii wide
                        $string7 = "cargo install sshx" nocase ascii wide
                        $string8 = "ekzhang/sshx" nocase ascii wide
                        $string9 = /https\:\/\/s3\.amazonaws\.com\/sshx\/sshx\-/ nocase ascii wide
                        $string10 = /https\:\/\/sshx\.io\/get/ nocase ascii wide
                        $string11 = /https\:\/\/sshx\.io\/s\// nocase ascii wide
                        $string12 = "sshx-server --listen" nocase ascii wide
                        $string13 = /sshx\-server\-.{0,1000}\.tar\.gz/ nocase ascii wide

    condition:
        any of them
}