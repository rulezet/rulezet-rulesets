rule SMBCrunch
{
    meta:
        description = "Detection patterns for the tool 'SMBCrunch' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SMBCrunch"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\-c\s.{0,1000}\s\-s\s.{0,1000}\s\-o\sshare_listing\s\-m\s150/ nocase ascii wide
                        $string2 = /\s\-i\sportscan445\.gnmap\s\-o\sshares_found\.txt/ nocase ascii wide
                        $string3 = /\sSMBGrab\.pl/ nocase ascii wide
                        $string4 = /\sSMBHunt\.pl/ nocase ascii wide
                        $string5 = /\sSMBList\.pl/ nocase ascii wide
                        $string6 = /\/SMBCrunch\.git/ nocase ascii wide
                        $string7 = /\/SMBGrab\.pl/ nocase ascii wide
                        $string8 = /\/SMBHunt\.pl/ nocase ascii wide
                        $string9 = /\/SMBList\.pl/ nocase ascii wide
                        $string10 = /\/tmp\/smb_auth_temp_.{0,1000}\.txt/
                        $string11 = /\\SMBGrab\.pl/ nocase ascii wide
                        $string12 = /\\SMBHunt\.pl/ nocase ascii wide
                        $string13 = /\\SMBList\.pl/ nocase ascii wide
                        $string14 = /No\scredentials\ssupplied.{0,1000}\slooking\sfor\snull\ssession\sshares\!/ nocase ascii wide
                        $string15 = "Raikia/SMBCrunch" nocase ascii wide
                        $string16 = /share_listing\/ALL_COMBINED_RESULTS\.TXT/ nocase ascii wide
                        $string17 = /smbclient\s\-N\s\-A\s.{0,1000}\\\\\\\\.{0,1000}\\\\.{0,1000}temp_out\.txt/ nocase ascii wide
                        $string18 = "SMBCrunch-master" nocase ascii wide
                        $string19 = "Starting enumerating file shares using domain credential for " nocase ascii wide

    condition:
        any of them
}