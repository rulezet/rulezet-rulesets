rule rule_LummaC2_Stealer_sample_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'LummaC2-Stealer-sample' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LummaC2-Stealer-sample"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_LummaC2_Stealer_sample_offensive_tool_keyword = "%appdaedx765ta%/Binaedx765nce" nocase ascii wide
                        $string2_LummaC2_Stealer_sample_offensive_tool_keyword = "%appdedx765ata%/Eledx765ectrum" nocase ascii wide
                        $string3_LummaC2_Stealer_sample_offensive_tool_keyword = "%appdedx765ata%/Etheedx765reum" nocase ascii wide
                        $string4_LummaC2_Stealer_sample_offensive_tool_keyword = "%localaedx765ppdata%" nocase ascii wide
                        $string5_LummaC2_Stealer_sample_offensive_tool_keyword = "%loedx765calappedx765data" nocase ascii wide
                        $string6_LummaC2_Stealer_sample_offensive_tool_keyword = "%userproedx765file%" nocase ascii wide
                        $string7_LummaC2_Stealer_sample_offensive_tool_keyword = /\.edx765txt/ nocase ascii wide
                        $string8_LummaC2_Stealer_sample_offensive_tool_keyword = /\\\\Edge\\\\Usedx765er\sData/ nocase ascii wide
                        $string9_LummaC2_Stealer_sample_offensive_tool_keyword = /\\\\Locedx765al\sStaedx765te/ nocase ascii wide
                        $string10_LummaC2_Stealer_sample_offensive_tool_keyword = /apedx765p\-stoedx765re\.jsedx765on/ nocase ascii wide
                        $string11_LummaC2_Stealer_sample_offensive_tool_keyword = "Binedx765ance Chaedx765in Waledx765let" nocase ascii wide
                        $string12_LummaC2_Stealer_sample_offensive_tool_keyword = /Brex765ave\-Broedx765wser\\\\Usedx765er\sData/ nocase ascii wide
                        $string13_LummaC2_Stealer_sample_offensive_tool_keyword = /Chredx765ome\\\\Usedx765er\sDatedx765a/ nocase ascii wide
                        $string14_LummaC2_Stealer_sample_offensive_tool_keyword = /Chroedx765mium\\\\Useedx765r\sData/ nocase ascii wide
                        $string15_LummaC2_Stealer_sample_offensive_tool_keyword = "Extedx765ensioedx765ns/" nocase ascii wide
                        $string16_LummaC2_Stealer_sample_offensive_tool_keyword = "ExtractFileInfoViaNTDLL" nocase ascii wide
                        $string17_LummaC2_Stealer_sample_offensive_tool_keyword = /ExtractFirefoxProfileData\(/ nocase ascii wide
                        $string18_LummaC2_Stealer_sample_offensive_tool_keyword = "Importedx765ant Fileedx765s/Proedx765file" nocase ascii wide
                        $string19_LummaC2_Stealer_sample_offensive_tool_keyword = "keystedx765ore" nocase ascii wide
                        $string20_LummaC2_Stealer_sample_offensive_tool_keyword = /Komedx765eta\\\\Usedx765er\sDaedx765ta/ nocase ascii wide
                        $string21_LummaC2_Stealer_sample_offensive_tool_keyword = "Locedx765al Extensedx765ion Settinedx765gs" nocase ascii wide
                        $string22_LummaC2_Stealer_sample_offensive_tool_keyword = "Loedx765gin Daedx765ta" nocase ascii wide
                        $string23_LummaC2_Stealer_sample_offensive_tool_keyword = "Logedx765in Daedx765ta Foedx765r Accedx765ount" nocase ascii wide
                        $string24_LummaC2_Stealer_sample_offensive_tool_keyword = "Meedx765taMaedx765sk" nocase ascii wide
                        $string25_LummaC2_Stealer_sample_offensive_tool_keyword = "Micedx765rosoft" nocase ascii wide
                        $string26_LummaC2_Stealer_sample_offensive_tool_keyword = /Moedx765zilla\\\\Firedx765efox\\\\Profedx765iles/ nocase ascii wide
                        $string27_LummaC2_Stealer_sample_offensive_tool_keyword = "Moziedx765lla Firefedx765ox" nocase ascii wide
                        $string28_LummaC2_Stealer_sample_offensive_tool_keyword = /Netwedx765ork\\\\Cookedx765ies/ nocase ascii wide
                        $string29_LummaC2_Stealer_sample_offensive_tool_keyword = /Opedx765era\sNeoedx765n\\\\Usedx765er\sDaedx765ta/ nocase ascii wide
                        $string30_LummaC2_Stealer_sample_offensive_tool_keyword = /Opedx765era\sSoftwedx765are\\\\Opedx765era\sGX\sStaedx765ble/ nocase ascii wide
                        $string31_LummaC2_Stealer_sample_offensive_tool_keyword = /Opeedx765ra\sSoftedx765ware\\\\Opedx765era\sStaedx765ble/ nocase ascii wide
                        $string32_LummaC2_Stealer_sample_offensive_tool_keyword = "resutlStrBrwsrOfshit" nocase ascii wide
                        $string33_LummaC2_Stealer_sample_offensive_tool_keyword = "Ronedx765in Walledx765et" nocase ascii wide
                        $string34_LummaC2_Stealer_sample_offensive_tool_keyword = "Troedx765nLiedx765nk" nocase ascii wide
                        $string35_LummaC2_Stealer_sample_offensive_tool_keyword = /Viedx765valdi\\\\Usedx765er\sData/ nocase ascii wide
                        $string36_LummaC2_Stealer_sample_offensive_tool_keyword = "Walledx765ets/Binanedx765ce" nocase ascii wide
                        $string37_LummaC2_Stealer_sample_offensive_tool_keyword = "Walledx765ets/Eleedx765ctrum" nocase ascii wide
                        $string38_LummaC2_Stealer_sample_offensive_tool_keyword = "Walledx765ets/Ethedx765ereum" nocase ascii wide
                        $string39_LummaC2_Stealer_sample_offensive_tool_keyword = "Wedx765eb Daedx765ta" nocase ascii wide
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