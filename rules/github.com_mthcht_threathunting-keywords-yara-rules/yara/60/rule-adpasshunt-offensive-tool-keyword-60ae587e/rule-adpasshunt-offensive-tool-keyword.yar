rule rule_ADPassHunt_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ADPassHunt' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ADPassHunt"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ADPassHunt_offensive_tool_keyword = /\sADPassHunt\.GetGPPPassword/ nocase ascii wide
                        $string2_ADPassHunt_offensive_tool_keyword = /\[ADA\]\sSearching\sfor\saccounts\swith\smsSFU30Password\sattribute/ nocase ascii wide
                        $string3_ADPassHunt_offensive_tool_keyword = /\[ADA\]\sSearching\sfor\saccounts\swith\suserpassword\sattribute/ nocase ascii wide
                        $string4_ADPassHunt_offensive_tool_keyword = /\[GPP\]\sSearching\sfor\spasswords\snow/ nocase ascii wide
                        $string5_ADPassHunt_offensive_tool_keyword = /\\ADPassHunt\.pdb/ nocase ascii wide
                        $string6_ADPassHunt_offensive_tool_keyword = /\\ADPassHunt\\/ nocase ascii wide
                        $string7_ADPassHunt_offensive_tool_keyword = ">ADPassHunt<" nocase ascii wide
                        $string8_ADPassHunt_offensive_tool_keyword = "73233ca7230fb5848e220723caa06d795a14c0f1f42c6a59482e812bfb8c217f" nocase ascii wide
                        $string9_ADPassHunt_offensive_tool_keyword = /AdPassHunt\s\(PUA\)/ nocase ascii wide
                        $string10_ADPassHunt_offensive_tool_keyword = /ADPassHunt\.exe/ nocase ascii wide
                        $string11_ADPassHunt_offensive_tool_keyword = "Get-GPPAutologons" nocase ascii wide
                        $string12_ADPassHunt_offensive_tool_keyword = "Get-GPPPasswords" nocase ascii wide
                        $string13_ADPassHunt_offensive_tool_keyword = "HackTool:Win32/PWDump" nocase ascii wide
                        $string14_ADPassHunt_offensive_tool_keyword = "HackTool:Win32/PWDump" nocase ascii wide
                        $string15_ADPassHunt_offensive_tool_keyword = /Win\.Tool\.ADPassHunt\-/ nocase ascii wide
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