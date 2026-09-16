rule rule_Alpemix_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Alpemix' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Alpemix"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_Alpemix_greyware_tool_keyword = /\/Alpemix\.zip/ nocase ascii wide
                        $string2_Alpemix_greyware_tool_keyword = /\/Apemix\.exe/ nocase ascii wide
                        $string3_Alpemix_greyware_tool_keyword = /\\Alpemix\.ini/ nocase ascii wide
                        $string4_Alpemix_greyware_tool_keyword = /\\Alpemix\.zip/ nocase ascii wide
                        $string5_Alpemix_greyware_tool_keyword = /\\Apemix\.exe/ nocase ascii wide
                        $string6_Alpemix_greyware_tool_keyword = /\\CurrentControlSet\\Services\\AlpemixSrvcx/ nocase ascii wide
                        $string7_Alpemix_greyware_tool_keyword = "<Alpemix>" nocase ascii wide
                        $string8_Alpemix_greyware_tool_keyword = "<AlpemixWEB>" nocase ascii wide
                        $string9_Alpemix_greyware_tool_keyword = "<Teknopars Bilisim>" nocase ascii wide
                        $string10_Alpemix_greyware_tool_keyword = "3660fe9f10b94d38fecaea009e6625850a46b1d47bb7788fc47f286c1008e2ec" nocase ascii wide
                        $string11_Alpemix_greyware_tool_keyword = "6badff5495258b349559b9d2154ffcc7a435828dd57c4caf1c79f5d0ff9eb675" nocase ascii wide
                        $string12_Alpemix_greyware_tool_keyword = "c5e68c5635bed872ce6ac0c2be5395cc15c2dbaa5f0052b86575cdd0b762902e" nocase ascii wide
                        $string13_Alpemix_greyware_tool_keyword = /serverinfo\.alpemix\.com/ nocase ascii wide
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