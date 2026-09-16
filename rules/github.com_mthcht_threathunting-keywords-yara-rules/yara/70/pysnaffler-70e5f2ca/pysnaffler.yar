rule pysnaffler
{
    meta:
        description = "Detection patterns for the tool 'pysnaffler' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pysnaffler"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\ssnaffler\.py\s/ nocase ascii wide
                        $string2 = /\.\/snaffler_downloads/
                        $string3 = /\/pysnaffler\.git/ nocase ascii wide
                        $string4 = /\/snaffler\.py/ nocase ascii wide
                        $string5 = /\\pysnaffler\\pysnaffler\\/ nocase ascii wide
                        $string6 = /\\snaffler\.py/ nocase ascii wide
                        $string7 = /from\spysnaffler\.rules\.constants\simport\s/ nocase ascii wide
                        $string8 = /from\spysnaffler\.rules\.rule\simport\sSnaffleRule/ nocase ascii wide
                        $string9 = /from\spysnaffler\.ruleset\simport\sSnafflerRuleSet/ nocase ascii wide
                        $string10 = /from\spysnaffler\.scanner\simport\sSnafflerScanner/ nocase ascii wide
                        $string11 = /from\spysnaffler\.snaffler\simport\s/ nocase ascii wide
                        $string12 = "pysnaffler -" nocase ascii wide
                        $string13 = /pysnaffler\s\'smb2\+kerberos\+password\:/ nocase ascii wide
                        $string14 = /pysnaffler\s\'smb2\+ntlm\-nt\:\/\// nocase ascii wide
                        $string15 = /pysnaffler\s\'smb2\+ntlm\-password\:\/\// nocase ascii wide
                        $string16 = /pysnaffler\.whatif\:main/ nocase ascii wide
                        $string17 = /pysnaffler\/_version\.py/ nocase ascii wide
                        $string18 = "pysnaffler-main" nocase ascii wide
                        $string19 = "skelsec/pysnaffler" nocase ascii wide
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