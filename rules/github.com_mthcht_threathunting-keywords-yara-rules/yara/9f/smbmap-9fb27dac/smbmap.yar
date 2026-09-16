rule smbmap
{
    meta:
        description = "Detection patterns for the tool 'smbmap' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "smbmap"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\-H\s.{0,100}\s\-u\s.{0,100}\s\-p\s.{0,100}\s\-r\s.{0,100}C\$\/Users/ nocase ascii wide
                        $string2 = /\s\-\-host\-file\s.{0,100}\.txt\s\-u\s.{0,100}\s\-\-prompt\s\-\-admin\s\-\-no\-banner/ nocase ascii wide
                        $string3 = /\/smbmap\.git/ nocase ascii wide
                        $string4 = /\\\\\\\\.{0,100}\\\\.{0,100}\\\\Get\-FileLockProcess\.ps1/ nocase ascii wide
                        $string5 = /cmd\s\/c\s.{0,100}if\sexist\s.{0,100}\.txt\secho\sImHere/ nocase ascii wide
                        $string6 = "install smbmap" nocase ascii wide
                        $string7 = "install smbmap" nocase ascii wide
                        $string8 = "ShawnDEvans/smbmap" nocase ascii wide
                        $string9 = "smbmap -" nocase ascii wide
                        $string10 = /smbmap\.py\s/ nocase ascii wide
                        $string11 = /smbmap\.smbmap/ nocase ascii wide
                        $string12 = "smbmap-master" nocase ascii wide
                        $string13 = /\-x\s.{0,100}net\sgroup\s.{0,100}Domain\sAdmins.{0,100}\s\/domain/ nocase ascii wide
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
            uint16(0) == 0x5a4d or             uint16(0) == 0x457f or             uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or             uint32(0) == 0x504B0304 or             uint32(0) == 0xCAFEBABE or             uint32(0) == 0x4D534346 or             uint32(0) == 0xD0CF11E0 or             uint16(0) == 0x2321 or             uint16(0) == 0x3c3f         )) and any of ($string*)) or
        (filesize < 2MB and
        (
            any of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}