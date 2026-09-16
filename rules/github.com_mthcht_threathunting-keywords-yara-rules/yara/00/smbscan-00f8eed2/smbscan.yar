rule smbscan
{
    meta:
        description = "Detection patterns for the tool 'smbscan' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "smbscan"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sCRITICAL\]\sSuspicous\sfile\:\s\\\\/ nocase ascii wide
                        $string2 = /\ssmbscan\.py\s/ nocase ascii wide
                        $string3 = /\/smbscan\-.{0,1000}\.csv/
                        $string4 = /\/smbscan\-.{0,1000}\.log/
                        $string5 = /\/smbscan\.git/ nocase ascii wide
                        $string6 = /\/smbscan\.py/ nocase ascii wide
                        $string7 = /\\smbscan\-.{0,1000}\.csv/ nocase ascii wide
                        $string8 = /\\smbscan\-.{0,1000}\.log/ nocase ascii wide
                        $string9 = /\\smbscan\.py/ nocase ascii wide
                        $string10 = "a4d92518de887211fcc6d0f0c011336140fa14d69a505223947a088cec3a9c0f" nocase ascii wide
                        $string11 = "dc9978d7-6299-4c5a-a22d-a039cdc716ea" nocase ascii wide
                        $string12 = /impacket\.smbconnection\.SMBConnection/ nocase ascii wide
                        $string13 = "jeffhacks/smbscan" nocase ascii wide

    condition:
        any of them
}