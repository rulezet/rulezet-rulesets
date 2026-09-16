rule rule_SpaceRunner_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SpaceRunner' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SpaceRunner"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SpaceRunner_offensive_tool_keyword = " -f Find-AllVulns" nocase ascii wide
                        $string2_SpaceRunner_offensive_tool_keyword = " -f Find-PathDLLHijack" nocase ascii wide
                        $string3_SpaceRunner_offensive_tool_keyword = /\s\-f\sGet\-DomainGroupMember.{0,100}\s\-a\s.{0,100}\-Identity\s.{0,100}admin.{0,100}\s\-Recurse/ nocase ascii wide
                        $string4_SpaceRunner_offensive_tool_keyword = " -f Invoke-Inveigh" nocase ascii wide
                        $string5_SpaceRunner_offensive_tool_keyword = /\/out\:spacerunner\.exe/ nocase ascii wide
                        $string6_SpaceRunner_offensive_tool_keyword = /\/SpaceRunner\.git/ nocase ascii wide
                        $string7_SpaceRunner_offensive_tool_keyword = /\/target\:exe\sspacerunner\.cs/ nocase ascii wide
                        $string8_SpaceRunner_offensive_tool_keyword = /\[\+\]\sGenerating\sbase64\sencoded\sPowerShell\sscript/ nocase ascii wide
                        $string9_SpaceRunner_offensive_tool_keyword = /\\inveigh\.exe/ nocase ascii wide
                        $string10_SpaceRunner_offensive_tool_keyword = /\\Powerup\.exe/ nocase ascii wide
                        $string11_SpaceRunner_offensive_tool_keyword = /\\Powerview\.exe/ nocase ascii wide
                        $string12_SpaceRunner_offensive_tool_keyword = /\\sherlock\.exe/ nocase ascii wide
                        $string13_SpaceRunner_offensive_tool_keyword = /beacon\.ps1.{0,100}beacon\.exe/ nocase ascii wide
                        $string14_SpaceRunner_offensive_tool_keyword = "Mr-B0b/SpaceRunner" nocase ascii wide
                        $string15_SpaceRunner_offensive_tool_keyword = /spacerunner\.exe\s\-i\s.{0,100}\.ps1.{0,100}\s\-o\s.{0,100}\.exe/ nocase ascii wide
                        $string16_SpaceRunner_offensive_tool_keyword = /SpaceRunner\-master\.zip/ nocase ascii wide
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