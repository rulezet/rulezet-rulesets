rule RustHound
{
    meta:
        description = "Detection patterns for the tool 'RustHound' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RustHound"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " --adcs --old-bloodhound " nocase ascii wide
                        $string2 = /\s\-c\sDCOnly\s\-d\s.{0,100}\s\-u\s.{0,100}\s\-p\s.{0,100}\s\-o\s\/tmp/ nocase ascii wide
                        $string3 = /\srusthound\.exe/ nocase ascii wide
                        $string4 = /\/rusthound\.exe/ nocase ascii wide
                        $string5 = /\/RustHound\.git/ nocase ascii wide
                        $string6 = /\\rusthound\.exe/ nocase ascii wide
                        $string7 = "--collectionmethod DCOnly" nocase ascii wide
                        $string8 = "OPENCYBER-FR/RustHound" nocase ascii wide
                        $string9 = /rusthound\s.{0,100}\-\-domain/ nocase ascii wide
                        $string10 = /rusthound\s.{0,100}\-\-ldapfqdn\s/ nocase ascii wide
                        $string11 = /rusthound\s.{0,100}\-ldaps\s/ nocase ascii wide
                        $string12 = "rusthound -c " nocase ascii wide
                        $string13 = "rusthound -d " nocase ascii wide
                        $string14 = "rusthound rusthound linux"
                        $string15 = "rusthound rusthound windows" nocase ascii wide
                        $string16 = /rusthound.{0,100}\s\-\-adcs\s\-\-dc\-only/ nocase ascii wide
                        $string17 = /rusthound\.exe/ nocase ascii wide
                        $string18 = "RustHound-main" nocase ascii wide
                        $string19 = /sharphound\.exe/ nocase ascii wide
                        $string20 = "usr/src/rusthound rusthound " nocase ascii wide
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