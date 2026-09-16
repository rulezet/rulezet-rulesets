rule nc
{
    meta:
        description = "Detection patterns for the tool 'nc' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nc"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\s\/bin\/nc\s.{0,100}\s\-e\s\/bin\/bash.{0,100}\s\>\scron\s\&\&\scrontab\scron/
                        $string2 = /\s\/bin\/nc\s.{0,100}\s\-e\s\/bin\/bash.{0,100}\>\s.{0,100}\scrontab\scron/
                        $string3 = "/nc64 -i "
                        $string4 = "/nc64 -lvp "
                        $string5 = "/nc64 -zv "
                        $string6 = /\\nc\.exe\s\-Ldp\s.{0,100}\s\-e\scmd\.exe/ nocase ascii wide
                        $string7 = /\\nc64\.exe\s\-i\s/ nocase ascii wide
                        $string8 = /\\nc64\.exe\s\-i/ nocase ascii wide
                        $string9 = /\\nc64\.exe\s\-lvp\s/ nocase ascii wide
                        $string10 = /\\nc64\.exe\s\-zv\s/ nocase ascii wide
                        $string11 = /\\nc64\.exe\\"\s\-i\s/ nocase ascii wide
                        $string12 = /\\nc64\.exe\\"\s\-lvp\s/ nocase ascii wide
                        $string13 = /\\nc64\.exe\\"\s\-zv\s/ nocase ascii wide
                        $string14 = /\\ncat.{0,100}\s\-e\scmd\.exe\s\-\-keep\-open/ nocase ascii wide
                        $string15 = /\\windows\\currentversion\\run\s\-v\snetcat\s/ nocase ascii wide
                        $string16 = /echo\snc\s\-l\s\-p\s.{0,100}\s\>\s.{0,100}\.bat/ nocase ascii wide
                        $string17 = /nc\s\-l\s\-p\s.{0,100}\s\-e\s.{0,100}\.bat/ nocase ascii wide
                        $string18 = /nc\s\-l\s\-p\s.{0,100}\s\-e\s\/bin\/bash/
                        $string19 = /nc\s\-l\s\-p\s.{0,100}\s\-e\scmd\.exe/ nocase ascii wide
                        $string20 = /nc\s\-v\s\-n\s\-z\s\-w1\s.{0,100}\-/ nocase ascii wide
                        $string21 = /nc\s\-z\s\-v\s.{0,100}\s/ nocase ascii wide
                        $string22 = /nc\.exe\s.{0,100}\s\-e\scmd\.exe\\"\s\/sc\sONCE\s/ nocase ascii wide
                        $string23 = /nc\.exe\s\-e\s\\windows\\system32\\cmd\.exe\s.{0,100}\sstart\=\sauto/ nocase ascii wide
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