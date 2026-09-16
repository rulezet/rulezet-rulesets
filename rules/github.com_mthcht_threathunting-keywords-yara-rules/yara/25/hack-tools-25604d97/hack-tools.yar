rule hack_tools
{
    meta:
        description = "Detection patterns for the tool 'hack-tools' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "hack-tools"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/Hack\-Tools\.git/ nocase ascii wide
                        $string2 = /cmbndhnoonmghfofefkcccljbkdpamhi_14678\.crx/ nocase ascii wide
                        $string3 = /hacktools\-.{0,1000}\.xpi/ nocase ascii wide
                        $string4 = "hack-tools/cmbndhnoonmghfofefkcccljbkdpamhi" nocase ascii wide
                        $string5 = "Hack-Tools-master" nocase ascii wide
                        $string6 = /https\:\/\/crackstation\.net\// nocase ascii wide
                        $string7 = "LasCC/Hack-Tools" nocase ascii wide

    condition:
        any of them
}