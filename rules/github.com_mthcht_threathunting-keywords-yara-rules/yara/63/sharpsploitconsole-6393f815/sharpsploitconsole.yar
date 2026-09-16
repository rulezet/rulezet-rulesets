rule SharpSploitConsole
{
    meta:
        description = "Detection patterns for the tool 'SharpSploitConsole' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpSploitConsole"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/SharpSploit\.dll/ nocase ascii wide
                        $string2 = /\/SharpSploitConsole\.git/ nocase ascii wide
                        $string3 = /\\SharpSploit\.dll/ nocase ascii wide
                        $string4 = /\\SharpSploitConsole\./ nocase ascii wide
                        $string5 = "3787435B-8352-4BD8-A1C6-E5A1B73921F4" nocase ascii wide
                        $string6 = "6511e5a343746d582d9e5f598ac329eb56ccde68429c880b1a9e551f5c27083d" nocase ascii wide
                        $string7 = "anthemtotheego/SharpSploitConsole" nocase ascii wide
                        $string8 = "c12b1320138b4fd7578d7b1b4741bba50f115c8dcf7c3eb3d30bf939de134ade" nocase ascii wide
                        $string9 = "Executes a chosen Mimikatz command" nocase ascii wide
                        $string10 = "Executes everything but DCSync - requires admin" nocase ascii wide
                        $string11 = "Kerberoast -username " nocase ascii wide
                        $string12 = "Mimi-Command " nocase ascii wide
                        $string13 = "Mimi-Command privilege::" nocase ascii wide
                        $string14 = "Performs a kerberoasting attack against targeted" nocase ascii wide
                        $string15 = "Retrieve Domain Cached Credentials hashes from registry" nocase ascii wide
                        $string16 = "Retrieve LSA secrets stored in registry" nocase ascii wide
                        $string17 = "Retrieve Wdigest credentials from registry" nocase ascii wide
                        $string18 = "Runs a powershell command while attempting to bypass AMSI" nocase ascii wide
                        $string19 = "SharpSploit Command Execution" nocase ascii wide
                        $string20 = "SharpSploit Credentials Commands" nocase ascii wide
                        $string21 = "SharpSploit Domain Enumeration Commands" nocase ascii wide
                        $string22 = "SharpSploit Enumeration Commands" nocase ascii wide
                        $string23 = "SharpSploit Lateral Movement Commands" nocase ascii wide
                        $string24 = /SharpSploit\.Enumeration\./ nocase ascii wide
                        $string25 = /sharpSploitConsole\.exe/ nocase ascii wide
                        $string26 = /SharpSploitConsole\.sln/ nocase ascii wide
                        $string27 = "SharpSploitConsole:>" nocase ascii wide
                        $string28 = "SharpSploitConsole-master" nocase ascii wide
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