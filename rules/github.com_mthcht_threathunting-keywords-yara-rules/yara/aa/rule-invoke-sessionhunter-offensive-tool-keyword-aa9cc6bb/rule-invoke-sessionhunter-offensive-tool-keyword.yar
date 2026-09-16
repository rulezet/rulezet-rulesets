rule rule_Invoke_SessionHunter_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Invoke-SessionHunter' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-SessionHunter"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Invoke_SessionHunter_offensive_tool_keyword = /\/Invoke\-SessionHunter\.git/ nocase ascii wide
                        $string2_Invoke_SessionHunter_offensive_tool_keyword = /\\Public\\Document\\SessionHunter\.txt/ nocase ascii wide
                        $string3_Invoke_SessionHunter_offensive_tool_keyword = "e721518ae125d596d4f5148ac0e7cc08d8b9efd62ce6d874fd5958e92b50346a" nocase ascii wide
                        $string4_Invoke_SessionHunter_offensive_tool_keyword = "fc0ceb113a9dd259d3f8029f0304e4be3ba72376a1d55b101b87b8d9e9b3a11a" nocase ascii wide
                        $string5_Invoke_SessionHunter_offensive_tool_keyword = "Invoke-SessionHunter " nocase ascii wide
                        $string6_Invoke_SessionHunter_offensive_tool_keyword = /Invoke\-SessionHunter\.ps1/ nocase ascii wide
                        $string7_Invoke_SessionHunter_offensive_tool_keyword = "Invoke-WMIRemoting " nocase ascii wide
                        $string8_Invoke_SessionHunter_offensive_tool_keyword = "Leo4j/Invoke-SessionHunter" nocase ascii wide
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