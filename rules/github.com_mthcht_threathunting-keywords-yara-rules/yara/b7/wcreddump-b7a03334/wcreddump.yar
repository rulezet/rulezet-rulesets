rule wcreddump
{
    meta:
        description = "Detection patterns for the tool 'wcreddump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wcreddump"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " install samdump2"
                        $string2 = /\swcreddump\s\(windows\scredentials\sdump\)/
                        $string3 = /\swcreddump\.py/
                        $string4 = /\sWINHELLO2hashcat\.py/
                        $string5 = /\/wcreddump\.git/
                        $string6 = /\/wcreddump\.py/
                        $string7 = /\/WINHELLO2hashcat\.py/
                        $string8 = /\\wcreddump\.py/
                        $string9 = /\\WINHELLO2hashcat\.py/
                        $string10 = "0d33356f9addc458bf9fc3861d9cafef954a51b66412b1cfc435eede351733f1"
                        $string11 = "samdump2 SYSTEM SAM"
                        $string12 = /succesfully\sdumped\sSAM\'s\shash\.es\sto\s/
                        $string13 = /succesfully\sdumped\sSAM\'s\shash\.es\sto\s/
                        $string14 = /succesfully\sdumped\sWINHELLO\spin\.s\sto\s/
                        $string15 = "truerustyy/wcreddump"
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