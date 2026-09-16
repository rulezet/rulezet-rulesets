rule SetProcessInjection
{
    meta:
        description = "Detection patterns for the tool 'SetProcessInjection' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SetProcessInjection"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/SetProcessInjection\.git/ nocase ascii wide
                        $string2 = /\[\+\]\sYour\spayload\smust\sbe\sexecuted\snow\s\!/ nocase ascii wide
                        $string3 = /\[x\]\sCannot\sload\sNTDLL\.DLL/ nocase ascii wide
                        $string4 = "azfvgayqKwtFApcvyRedpUXculaeCCGA" nocase ascii wide
                        $string5 = "CA280845-1F10-4E65-9DE7-D9C6513BBD91" nocase ascii wide
                        $string6 = "OtterHacker/SetProcessInjection" nocase ascii wide
                        $string7 = /payload\/encryptor_remote\.py/ nocase ascii wide
                        $string8 = /SetProcessInjection.{0,100}encryptor\.py/ nocase ascii wide
                        $string9 = "SetProcessInjection-main" nocase ascii wide
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