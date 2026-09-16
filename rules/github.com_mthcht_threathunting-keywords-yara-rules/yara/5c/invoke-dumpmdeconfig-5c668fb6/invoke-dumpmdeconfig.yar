rule Invoke_DumpMDEConfig
{
    meta:
        description = "Detection patterns for the tool 'Invoke-DumpMDEConfig' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-DumpMDEConfig"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\[\+\]\sDefender\sConfig\sDumped\sto\s/ nocase ascii wide
                        $string2 = /\[\+\]\sDumped\sAllowed\sThreats\sto\s.{0,100}\s/ nocase ascii wide
                        $string3 = /\[\+\]\sDumped\sExclusion\sPaths\sto\sExclusionPaths\.csv/ nocase ascii wide
                        $string4 = /\[\+\]\sDumped\sExploit\sGuard\sProtection\sHistory/ nocase ascii wide
                        $string5 = /\[\+\]\sDumped\sFirewall\sExclusions\sto\s/ nocase ascii wide
                        $string6 = /\[\+\]\sDumped\sProtection\sHistory\sto\sProtectionHistory\.csv/ nocase ascii wide
                        $string7 = /\[\+\]\sDumping\sDefender\sExcluded\sPaths/ nocase ascii wide
                        $string8 = /\[\+\]\sDumping\sDefender\sProtection\sHistory/ nocase ascii wide
                        $string9 = /\[\+\]\sDumping\sEnabled\sASR\sRules/ nocase ascii wide
                        $string10 = /\[System\[Provider\[\@Name\=\'Microsoft\-Windows\-Windows\sDefender\'\]\sand\s\(EventID\=5007\)\]\]/ nocase ascii wide
                        $string11 = /\\ExploitGuardProtectionHistory\.csv/ nocase ascii wide
                        $string12 = "78a098cf3b91a354d6425bb5c08af4a0cc137a71bec4ad44707d864e263a4384" nocase ascii wide
                        $string13 = "Invoke-DumpMDEConfig" nocase ascii wide
                        $string14 = "Query-ExploitGuardProtectionHistory " nocase ascii wide
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