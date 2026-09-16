rule IMDSpoof
{
    meta:
        description = "Detection patterns for the tool 'IMDSpoof' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "IMDSpoof"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/etc\/systemd\/system\/IMDS\.service/
                        $string2 = /\/IMDSpoof\.git/ nocase ascii wide
                        $string3 = "grahamhelton/IMDSpoof" nocase ascii wide
                        $string4 = "IMDS Service Spoofing Enabled" nocase ascii wide
                        $string5 = "IMDSPoof Honey Token" nocase ascii wide
                        $string6 = /IMDSpoof.{0,1000}IMDS\.go/ nocase ascii wide
                        $string7 = "IMDSpoof-main" nocase ascii wide
                        $string8 = "IQoJb3Jpz2cXpQRkpVX3Uf" nocase ascii wide
                        $string9 = "systemctl disable IMDS" nocase ascii wide
                        $string10 = "systemctl enable IMDS" nocase ascii wide
                        $string11 = "systemctl start IMDS" nocase ascii wide
                        $string12 = "systemctl status IMDS" nocase ascii wide
                        $string13 = "systemctl stop IMDS" nocase ascii wide

    condition:
        any of them
}