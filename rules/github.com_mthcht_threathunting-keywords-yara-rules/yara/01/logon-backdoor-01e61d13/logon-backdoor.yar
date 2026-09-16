rule logon_backdoor
{
    meta:
        description = "Detection patterns for the tool 'logon_backdoor' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "logon_backdoor"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/backdoor\.bat/ nocase ascii wide
                        $string2 = /\/backdoor\.exe/ nocase ascii wide
                        $string3 = /\/logon_backdoor\.git/ nocase ascii wide
                        $string4 = /\[\sbackdoor\s\-\sDebug\s\]/ nocase ascii wide
                        $string5 = /\\backdoor\.bat/ nocase ascii wide
                        $string6 = /\\backdoor\.exe/ nocase ascii wide
                        $string7 = /\\backdoor\\backdoor\.mk/ nocase ascii wide
                        $string8 = /\\backdoor\\backdoor\.project/ nocase ascii wide
                        $string9 = /\\backdoor_new\.bat/ nocase ascii wide
                        $string10 = /\\logon_backdoor\\/ nocase ascii wide
                        $string11 = /\\logon_backdoor\-master/ nocase ascii wide
                        $string12 = /\\oem\\Desktop\\backdoor/ nocase ascii wide
                        $string13 = /\'1\.\sSet\sthe\sbackdoor\'/ nocase ascii wide
                        $string14 = "59a64374f430585117c385edce4ac8ff536cb2710a0037384f9f869601752af1" nocase ascii wide
                        $string15 = "6e0055eba5cf62d9ac7b129e55d3f230fef2dd432d88313ae08d85d9ff5c2329" nocase ascii wide
                        $string16 = "a93f02549ee6f5a59d0472755b8719284f64e0ac451906a42d8eb9f5738add67" nocase ascii wide
                        $string17 = "Backdoor has been set up successfully" nocase ascii wide
                        $string18 = /Backdoor\sis\salready\sremoved\s\:\)/ nocase ascii wide
                        $string19 = /Backdoor\sis\salready\sset\sup\s\;\)/ nocase ascii wide
                        $string20 = /REG\sDELETE\s\\"HKLM\\SOFTWARE\\Microsoft\\Windows\sNT\\CurrentVersion\\Image\sFile\sExecution\sOptions\\sethc\.exe\\"/ nocase ascii wide
                        $string21 = "szymon1118/logon_backdoor" nocase ascii wide
                        $string22 = "title logon backdoor" nocase ascii wide
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