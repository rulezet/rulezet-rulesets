rule rule_SMBCrunch_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SMBCrunch' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SMBCrunch"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SMBCrunch_offensive_tool_keyword = /\s\-c\s.{0,1000}\s\-s\s.{0,1000}\s\-o\sshare_listing\s\-m\s150/ nocase ascii wide
                        $string2_SMBCrunch_offensive_tool_keyword = /\s\-i\sportscan445\.gnmap\s\-o\sshares_found\.txt/ nocase ascii wide
                        $string3_SMBCrunch_offensive_tool_keyword = /\sSMBGrab\.pl/ nocase ascii wide
                        $string4_SMBCrunch_offensive_tool_keyword = /\sSMBHunt\.pl/ nocase ascii wide
                        $string5_SMBCrunch_offensive_tool_keyword = /\sSMBList\.pl/ nocase ascii wide
                        $string6_SMBCrunch_offensive_tool_keyword = /\/SMBCrunch\.git/ nocase ascii wide
                        $string7_SMBCrunch_offensive_tool_keyword = /\/SMBGrab\.pl/ nocase ascii wide
                        $string8_SMBCrunch_offensive_tool_keyword = /\/SMBHunt\.pl/ nocase ascii wide
                        $string9_SMBCrunch_offensive_tool_keyword = /\/SMBList\.pl/ nocase ascii wide
                        $string10_SMBCrunch_offensive_tool_keyword = /\/tmp\/smb_auth_temp_.{0,1000}\.txt/
                        $string11_SMBCrunch_offensive_tool_keyword = /\\SMBGrab\.pl/ nocase ascii wide
                        $string12_SMBCrunch_offensive_tool_keyword = /\\SMBHunt\.pl/ nocase ascii wide
                        $string13_SMBCrunch_offensive_tool_keyword = /\\SMBList\.pl/ nocase ascii wide
                        $string14_SMBCrunch_offensive_tool_keyword = /No\scredentials\ssupplied.{0,1000}\slooking\sfor\snull\ssession\sshares\!/ nocase ascii wide
                        $string15_SMBCrunch_offensive_tool_keyword = "Raikia/SMBCrunch" nocase ascii wide
                        $string16_SMBCrunch_offensive_tool_keyword = /share_listing\/ALL_COMBINED_RESULTS\.TXT/ nocase ascii wide
                        $string17_SMBCrunch_offensive_tool_keyword = /smbclient\s\-N\s\-A\s.{0,1000}\\\\\\\\.{0,1000}\\\\.{0,1000}temp_out\.txt/ nocase ascii wide
                        $string18_SMBCrunch_offensive_tool_keyword = "SMBCrunch-master" nocase ascii wide
                        $string19_SMBCrunch_offensive_tool_keyword = "Starting enumerating file shares using domain credential for " nocase ascii wide

    condition:
        any of them
}