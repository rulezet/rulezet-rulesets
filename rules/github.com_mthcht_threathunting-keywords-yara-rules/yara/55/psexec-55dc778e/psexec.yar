rule psexec
{
    meta:
        description = "Detection patterns for the tool 'psexec' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "psexec"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\s\-accepteula\s\-nobanner\s\-d\scmd\.exe\s\/c\s/ nocase ascii wide
                        $string2 = /\.exe\s\/i\s\/s\scmd\s/ nocase ascii wide
                        $string3 = /\.exe\s\/i\s\/s\scmd\.exe/ nocase ascii wide
                        $string4 = /\.exe\s\/i\s\/s\spowershell/ nocase ascii wide
                        $string5 = /\.exe\s\/i\s\/s\spwsh/ nocase ascii wide
                        $string6 = /\.exe\s\/s\s\/i\scmd\.exe/ nocase ascii wide
                        $string7 = /\.exe\s\/s\s\/i\spowershell/ nocase ascii wide
                        $string8 = /\.exe\s\/s\s\/i\spwsh/ nocase ascii wide
                        $string9 = /\.exe\s\-i\s\-s\scmd\s/ nocase ascii wide
                        $string10 = /\.exe\s\-i\s\-s\scmd\s/ nocase ascii wide
                        $string11 = /\.exe\s\-i\s\-s\scmd\.exe/ nocase ascii wide
                        $string12 = /\.exe\s\-i\s\-s\spowershell/ nocase ascii wide
                        $string13 = /\.exe\s\-i\s\-s\spwsh/ nocase ascii wide
                        $string14 = /\.exe\s\-s\s\-i\scmd\.exe/ nocase ascii wide
                        $string15 = /\.exe\s\-s\s\-i\spowershell/ nocase ascii wide
                        $string16 = /\.exe\s\-s\s\-i\spwsh/ nocase ascii wide
                        $string17 = /\\PsExec\.exe/ nocase ascii wide
                        $string18 = /\\SOFTWARE\\Sysinternals\\PsExec\\EulaAccepted/ nocase ascii wide
                        $string19 = /\\Windows\\Prefetch\\PSEXEC/ nocase ascii wide
                        $string20 = /\\Windows\\PSEXEC\-.{0,100}\.key/ nocase ascii wide
                        $string21 = /PSEXEC\-.{0,100}\.key/ nocase ascii wide
                        $string22 = /PsExec\.exe\s\/accepteula/ nocase ascii wide
                        $string23 = /PsExec\[1\]\.exe/ nocase ascii wide
                        $string24 = /PsExec64\.exe/ nocase ascii wide
                        $string25 = "PSEXECSVC" nocase ascii wide
                        $string26 = /PSEXECSVC\.EXE\-.{0,100}\.pf/ nocase ascii wide
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