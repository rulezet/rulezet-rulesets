rule rule_hack_tools_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'hack-tools' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "hack-tools"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_hack_tools_offensive_tool_keyword = /\/Hack\-Tools\.git/ nocase ascii wide
                        $string2_hack_tools_offensive_tool_keyword = /cmbndhnoonmghfofefkcccljbkdpamhi_14678\.crx/ nocase ascii wide
                        $string3_hack_tools_offensive_tool_keyword = /hacktools\-.{0,1000}\.xpi/ nocase ascii wide
                        $string4_hack_tools_offensive_tool_keyword = "hack-tools/cmbndhnoonmghfofefkcccljbkdpamhi" nocase ascii wide
                        $string5_hack_tools_offensive_tool_keyword = "Hack-Tools-master" nocase ascii wide
                        $string6_hack_tools_offensive_tool_keyword = /https\:\/\/crackstation\.net\// nocase ascii wide
                        $string7_hack_tools_offensive_tool_keyword = "LasCC/Hack-Tools" nocase ascii wide

    condition:
        any of them
}