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
                        $string4 = /\sowa\s.{0,100}\s\-\-user\-as\-pass\s/ nocase ascii wide
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
                        $string27 = /owa\s.{0,100}\/autodiscover\/autodiscover\.xml.{0,100}\s\-\-recon/ nocase ascii wide
                        $string28 = /self\.sprayer\.auth_O365/ nocase ascii wide
                        $string29 = /spindrift\.py\s.{0,100}\-\-target\s/ nocase ascii wide
                        $string30 = /spindrift\.py\s\-\-domain/ nocase ascii wide
                        $string31 = /SprayingToolkit\.git/ nocase ascii wide
                        $string32 = "SprayingToolkit-master" nocase ascii wide
                        $string33 = /SprayingToolkit\-master\.zip/ nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or             uint16(0) == 0x457f or             uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or             uint32(0) == 0x504B0304 or             uint32(0) == 0xCAFEBABE or             uint32(0) == 0x4D534346 or             uint32(0) == 0xD0CF11E0 or             uint16(0) == 0x2321 or             uint16(0) == 0x3c3f         )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}