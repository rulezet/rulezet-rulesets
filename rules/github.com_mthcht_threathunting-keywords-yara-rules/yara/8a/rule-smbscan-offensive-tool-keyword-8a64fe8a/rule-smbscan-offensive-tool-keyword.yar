rule rule_smbscan_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'smbscan' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "smbscan"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_smbscan_offensive_tool_keyword = /\sCRITICAL\]\sSuspicous\sfile\:\s\\\\/ nocase ascii wide
                        $string2_smbscan_offensive_tool_keyword = /\ssmbscan\.py\s/ nocase ascii wide
                        $string3_smbscan_offensive_tool_keyword = /\/smbscan\-.{0,1000}\.csv/
                        $string4_smbscan_offensive_tool_keyword = /\/smbscan\-.{0,1000}\.log/
                        $string5_smbscan_offensive_tool_keyword = /\/smbscan\.git/ nocase ascii wide
                        $string6_smbscan_offensive_tool_keyword = /\/smbscan\.py/ nocase ascii wide
                        $string7_smbscan_offensive_tool_keyword = /\\smbscan\-.{0,1000}\.csv/ nocase ascii wide
                        $string8_smbscan_offensive_tool_keyword = /\\smbscan\-.{0,1000}\.log/ nocase ascii wide
                        $string9_smbscan_offensive_tool_keyword = /\\smbscan\.py/ nocase ascii wide
                        $string10_smbscan_offensive_tool_keyword = "a4d92518de887211fcc6d0f0c011336140fa14d69a505223947a088cec3a9c0f" nocase ascii wide
                        $string11_smbscan_offensive_tool_keyword = "dc9978d7-6299-4c5a-a22d-a039cdc716ea" nocase ascii wide
                        $string12_smbscan_offensive_tool_keyword = /impacket\.smbconnection\.SMBConnection/ nocase ascii wide
                        $string13_smbscan_offensive_tool_keyword = "jeffhacks/smbscan" nocase ascii wide

    condition:
        any of them
}