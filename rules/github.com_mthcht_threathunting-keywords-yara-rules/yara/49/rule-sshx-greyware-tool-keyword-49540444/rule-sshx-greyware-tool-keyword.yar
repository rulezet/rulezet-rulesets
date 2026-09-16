rule rule_sshx_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'sshx' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sshx"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_sshx_greyware_tool_keyword = " --bin sshx-server" nocase ascii wide
                        $string2_sshx_greyware_tool_keyword = " s3://sshx/" nocase ascii wide
                        $string3_sshx_greyware_tool_keyword = /\.vm\.sshx\.internal\:8051/ nocase ascii wide
                        $string4_sshx_greyware_tool_keyword = "/release/sshx-server" nocase ascii wide
                        $string5_sshx_greyware_tool_keyword = "/sshx-server/" nocase ascii wide
                        $string6_sshx_greyware_tool_keyword = /\\sshx\-.{0,1000}\.tar\.gz/ nocase ascii wide
                        $string7_sshx_greyware_tool_keyword = "cargo install sshx" nocase ascii wide
                        $string8_sshx_greyware_tool_keyword = "ekzhang/sshx" nocase ascii wide
                        $string9_sshx_greyware_tool_keyword = /https\:\/\/s3\.amazonaws\.com\/sshx\/sshx\-/ nocase ascii wide
                        $string10_sshx_greyware_tool_keyword = /https\:\/\/sshx\.io\/get/ nocase ascii wide
                        $string11_sshx_greyware_tool_keyword = /https\:\/\/sshx\.io\/s\// nocase ascii wide
                        $string12_sshx_greyware_tool_keyword = "sshx-server --listen" nocase ascii wide
                        $string13_sshx_greyware_tool_keyword = /sshx\-server\-.{0,1000}\.tar\.gz/ nocase ascii wide

    condition:
        any of them
}