rule findstr
{
    meta:
        description = "Detection patterns for the tool 'findstr' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "findstr"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /dir\s\/a\sC\:\\pagefile\.sys\s\|\sfindstr\s\/R\s/ nocase ascii wide
                        $string2 = /findstr\s.{0,1000}cpassword\s.{0,1000}\\sysvol\\.{0,1000}\.xml/ nocase ascii wide
                        $string3 = /findstr\s.{0,1000}vnc\.ini/ nocase ascii wide
                        $string4 = /findstr\s\/S\scpassword\s\$env\:.{0,1000}\\sysvol\\.{0,1000}\.xml/ nocase ascii wide
                        $string5 = /findstr\s\/S\scpassword\s\%.{0,1000}\%\\sysvol\\.{0,1000}\.xml/ nocase ascii wide
                        $string6 = /findstr\s\/si\ssecret\s.{0,1000}\.docx/ nocase ascii wide

    condition:
        any of them
}