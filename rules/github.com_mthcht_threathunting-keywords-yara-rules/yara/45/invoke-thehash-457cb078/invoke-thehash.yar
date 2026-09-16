rule Invoke_TheHash
{
    meta:
        description = "Detection patterns for the tool 'Invoke-TheHash' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-TheHash"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\-Type\sSMBClient\s\-Target\s.{0,100}\s\-TargetExclude\s.{0,100}\s\-Username\s.{0,100}\s\-Hash\s/ nocase ascii wide
                        $string2 = /\s\-Type\sSMBEnum\s\-Target\s.{0,100}\s\-TargetExclude\s.{0,100}\s\-Username\s.{0,100}\s\-Hash\s/ nocase ascii wide
                        $string3 = /\s\-Type\sSMBExec\s\-Target\s.{0,100}\s\-TargetExclude\s.{0,100}\s\-Username\s.{0,100}\s\-Hash\s/ nocase ascii wide
                        $string4 = " -Type WMIExec " nocase ascii wide
                        $string5 = /\s\-Type\sWMIExec\s\-Target\s.{0,100}\s\-TargetExclude\s.{0,100}\s\-Username\s.{0,100}\s\-Hash\s/ nocase ascii wide
                        $string6 = /\[\-\]\s.{0,100}\sdoes\snot\shave\sService\sControl\sManager\swrite\sprivilege\son\s/ nocase ascii wide
                        $string7 = /\[\-\]\sInveigh\sRelay\ssession\s/ nocase ascii wide
                        $string8 = /Invoke\-SMBClient\.ps1/ nocase ascii wide
                        $string9 = "Invoke-SMBEnum" nocase ascii wide
                        $string10 = "Invoke-SMBExec" nocase ascii wide
                        $string11 = "Invoke-TheHash" nocase ascii wide
                        $string12 = /Invoke\-TheHash\.ps1/ nocase ascii wide
                        $string13 = /Invoke\-TheHash\.psd1/ nocase ascii wide
                        $string14 = /Invoke\-TheHash\.psm1/ nocase ascii wide
                        $string15 = "Invoke-WMIExec " nocase ascii wide
                        $string16 = /Invoke\-WMIExec\.ps1/ nocase ascii wide
                        $string17 = "New-PacketSMB2IoctlRequest" nocase ascii wide
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