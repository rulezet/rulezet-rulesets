rule rule_EASSniper_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'EASSniper' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EASSniper"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_EASSniper_offensive_tool_keyword = /\sEASSniper\.ps1/ nocase ascii wide
                        $string2_EASSniper_offensive_tool_keyword = /\seas\-valid\-users\.txt/ nocase ascii wide
                        $string3_EASSniper_offensive_tool_keyword = /\sowa\-sprayed\-creds\.txt/ nocase ascii wide
                        $string4_EASSniper_offensive_tool_keyword = /\/EASSniper\.git/ nocase ascii wide
                        $string5_EASSniper_offensive_tool_keyword = /\/EASSniper\.ps1/ nocase ascii wide
                        $string6_EASSniper_offensive_tool_keyword = /\/eas\-valid\-users\.txt/
                        $string7_EASSniper_offensive_tool_keyword = /\/owa\-sprayed\-creds\.txt/
                        $string8_EASSniper_offensive_tool_keyword = /\\EASSniper\.ps1/ nocase ascii wide
                        $string9_EASSniper_offensive_tool_keyword = /\\eas\-valid\-users\.txt/ nocase ascii wide
                        $string10_EASSniper_offensive_tool_keyword = /\\owa\-sprayed\-creds\.txt/ nocase ascii wide
                        $string11_EASSniper_offensive_tool_keyword = /\]\sNow\sspraying\sEAS\sportal\sat\shttps\:\/\/.{0,100}\/Microsoft\-Server\-ActiveSync/ nocase ascii wide
                        $string12_EASSniper_offensive_tool_keyword = "002fa7c3b308536f94ff10852afcfbb0285608d259a43277e69751ab7db48e04" nocase ascii wide
                        $string13_EASSniper_offensive_tool_keyword = "fugawi/EASSniper" nocase ascii wide
                        $string14_EASSniper_offensive_tool_keyword = "Invoke-PasswordSprayEAS" nocase ascii wide
                        $string15_EASSniper_offensive_tool_keyword = "Invoke-UsernameHarvestEAS" nocase ascii wide
                        $string16_EASSniper_offensive_tool_keyword = "Password Spraying EAS at https://" nocase ascii wide
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