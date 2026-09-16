rule ContainYourself
{
    meta:
        description = "Detection patterns for the tool 'ContainYourself' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ContainYourself"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\-\-copy\-file\s\-\-source\-file\s.{0,100}\.docx\s\-\-target\-file\s.{0,100}\.docx\s\-\-target\-volume\s/ nocase ascii wide
                        $string2 = /\.exe\s\-\-override\-file\s\-\-source\-file\s.{0,100}\.exe/ nocase ascii wide
                        $string3 = /\.exe\s\-\-remove\-reparse\s\-\-source\-file\s.{0,100}\.exe/ nocase ascii wide
                        $string4 = /\.exe\s\-\-set\-reparse\soverride\s\-\-source\-file\s.{0,100}\.exe\s\-\-target\-file\s/ nocase ascii wide
                        $string5 = /\/ContainYourself\.git/ nocase ascii wide
                        $string6 = /\\WiperPoc\.cpp/ nocase ascii wide
                        $string7 = "4F2AD0E0-8C4D-45CB-97DE-CE8D4177E7BF" nocase ascii wide
                        $string8 = "79F54747-048D-4FD6-AEF4-7B098F923FD8" nocase ascii wide
                        $string9 = "B5627919-4DFB-49C6-AC1B-C757F4B4A103" nocase ascii wide
                        $string10 = /ContainYourself\.cpp/ nocase ascii wide
                        $string11 = /ContainYourself\.exe/ nocase ascii wide
                        $string12 = /ContainYourself\.sln/ nocase ascii wide
                        $string13 = "ContainYourself-main" nocase ascii wide
                        $string14 = /ContainYourselfPoc\.cpp/ nocase ascii wide
                        $string15 = /ContainYourselfPoc\.exe/ nocase ascii wide
                        $string16 = /ContainYourselfPoc\\/ nocase ascii wide
                        $string17 = /ContainYourselfTempFile\.txt/ nocase ascii wide
                        $string18 = "deepinstinct/ContainYourself" nocase ascii wide
                        $string19 = "FA0DAF13-5058-4382-AE07-65E44AFB5592" nocase ascii wide
                        $string20 = "Ransomware POC tool that encrypts a given directory" nocase ascii wide
                        $string21 = /RansomwarePoc\.cpp/ nocase ascii wide
                        $string22 = /RansomwarePoc\.exe/ nocase ascii wide
                        $string23 = /RansomwarePoc\\RansomwarePoc/ nocase ascii wide
                        $string24 = "Wiper POC tool that wipes a given directory" nocase ascii wide
                        $string25 = /WiperPoc\.exe/ nocase ascii wide
                        $string26 = /WiperPoc\\WiperPoc/ nocase ascii wide
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