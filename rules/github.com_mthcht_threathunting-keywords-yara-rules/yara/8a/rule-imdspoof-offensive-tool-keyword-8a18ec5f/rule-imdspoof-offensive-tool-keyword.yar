rule rule_IMDSpoof_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'IMDSpoof' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "IMDSpoof"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_IMDSpoof_offensive_tool_keyword = /\/etc\/systemd\/system\/IMDS\.service/
                        $string2_IMDSpoof_offensive_tool_keyword = /\/IMDSpoof\.git/ nocase ascii wide
                        $string3_IMDSpoof_offensive_tool_keyword = "grahamhelton/IMDSpoof" nocase ascii wide
                        $string4_IMDSpoof_offensive_tool_keyword = "IMDS Service Spoofing Enabled" nocase ascii wide
                        $string5_IMDSpoof_offensive_tool_keyword = "IMDSPoof Honey Token" nocase ascii wide
                        $string6_IMDSpoof_offensive_tool_keyword = /IMDSpoof.{0,1000}IMDS\.go/ nocase ascii wide
                        $string7_IMDSpoof_offensive_tool_keyword = "IMDSpoof-main" nocase ascii wide
                        $string8_IMDSpoof_offensive_tool_keyword = "IQoJb3Jpz2cXpQRkpVX3Uf" nocase ascii wide
                        $string9_IMDSpoof_offensive_tool_keyword = "systemctl disable IMDS" nocase ascii wide
                        $string10_IMDSpoof_offensive_tool_keyword = "systemctl enable IMDS" nocase ascii wide
                        $string11_IMDSpoof_offensive_tool_keyword = "systemctl start IMDS" nocase ascii wide
                        $string12_IMDSpoof_offensive_tool_keyword = "systemctl status IMDS" nocase ascii wide
                        $string13_IMDSpoof_offensive_tool_keyword = "systemctl stop IMDS" nocase ascii wide

    condition:
        any of them
}