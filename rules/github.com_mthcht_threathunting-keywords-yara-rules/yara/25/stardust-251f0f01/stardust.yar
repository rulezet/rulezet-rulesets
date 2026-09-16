rule Stardust
{
    meta:
        description = "Detection patterns for the tool 'Stardust' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Stardust"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "\"Stardust MessageBox\"" nocase ascii wide
                        $string2 = /\/stardust\.x64\.exe/ nocase ascii wide
                        $string3 = /\/Stardust\/scripts\/loader\.x64\.exe/ nocase ascii wide
                        $string4 = /\/x64\/Stardust\.asm/ nocase ascii wide
                        $string5 = /\[\+\]\sExecute\sshellcode\.\.\.\spress\senter/ nocase ascii wide
                        $string6 = /\\stardust\.x64\.bin/ nocase ascii wide
                        $string7 = /\\stardust\.x64\.exe/ nocase ascii wide
                        $string8 = /\\Stardust\\scripts\\loader\.x64\.exe/ nocase ascii wide
                        $string9 = /\\x64\\Stardust\.asm/ nocase ascii wide
                        $string10 = /bin\/stardust\.x64\.bin/ nocase ascii wide
                        $string11 = /https\:\/\/5pider\.net\/blog\/2024\/01\/27\/modern\-shellcode\-implant\-design/ nocase ascii wide
                        $string12 = /loader\.x64\.exe\.exe/ nocase ascii wide
                        $string13 = /Stardust\.Win32\.NtProtectVirtualMemory\(/ nocase ascii wide
                        $string14 = /Stardust\.Win32\.RtlAllocateHeap\(/ nocase ascii wide
                        $string15 = "STARDUST_MACROS_H" nocase ascii wide
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