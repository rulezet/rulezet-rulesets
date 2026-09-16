rule SprayingToolkit
{
    meta:
        description = "Detection patterns for the tool 'SprayingToolkit' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SprayingToolkit"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\satomizer\.py\s/ nocase ascii wide
                        $string2 = /\sLyncSniper\.ps1/ nocase ascii wide
                        $string3 = /\sntlmdecoder\.py/ nocase ascii wide
                        $string4 = /\sowa\s.{0,1000}\s\-\-user\-as\-pass\s/ nocase ascii wide
                        $string5 = /\svaporizer\.py\s/ nocase ascii wide
                        $string6 = /\/aerosol\.py/
                        $string7 = /\/atomizer\.py/
                        $string8 = /\/LyncSniper\.ps1/ nocase ascii wide
                        $string9 = /\/ntlmdecoder\.py/ nocase ascii wide
                        $string10 = /\/sprayers\/owa\.py/ nocase ascii wide
                        $string11 = "/SprayingToolkit" nocase ascii wide
                        $string12 = /\/SprayingToolkit\.git/
                        $string13 = /\\LyncSniper\.ps1/ nocase ascii wide
                        $string14 = /\\ntlmdecoder\.py/ nocase ascii wide
                        $string15 = "6f46d85ab9aef2bf824b8714f29f9ff189a390c56294ab82308178e86fad472d" nocase ascii wide
                        $string16 = "atomizer imap " nocase ascii wide
                        $string17 = "atomizer lync " nocase ascii wide
                        $string18 = "atomizer owa " nocase ascii wide
                        $string19 = /atomizer\.py\s\-/ nocase ascii wide
                        $string20 = /atomizer\.py\simap\s/ nocase ascii wide
                        $string21 = /atomizer\.py\slync\s/ nocase ascii wide
                        $string22 = /atomizer\.py\sowa\s/ nocase ascii wide
                        $string23 = "byt3bl33d3r/SprayingToolkit" nocase ascii wide
                        $string24 = /core\/sprayers\/lync\.py/ nocase ascii wide
                        $string25 = "dbb049e7216149b1723b7dbbf9e3e80ce4a0f2d78b2afa8b2cf451c1e5d97b91" nocase ascii wide
                        $string26 = /mitmdump\s\-s\saerosol\.py/ nocase ascii wide
                        $string27 = /owa\s.{0,1000}\/autodiscover\/autodiscover\.xml.{0,1000}\s\-\-recon/ nocase ascii wide
                        $string28 = /self\.sprayer\.auth_O365/ nocase ascii wide
                        $string29 = /spindrift\.py\s.{0,1000}\-\-target\s/ nocase ascii wide
                        $string30 = /spindrift\.py\s\-\-domain/ nocase ascii wide
                        $string31 = /SprayingToolkit\.git/ nocase ascii wide
                        $string32 = "SprayingToolkit-master" nocase ascii wide
                        $string33 = /SprayingToolkit\-master\.zip/ nocase ascii wide

    condition:
        any of them
}