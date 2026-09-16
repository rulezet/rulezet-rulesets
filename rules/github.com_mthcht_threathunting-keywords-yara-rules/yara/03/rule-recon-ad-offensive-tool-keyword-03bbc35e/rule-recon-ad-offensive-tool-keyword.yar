rule rule_Recon_AD_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Recon-AD' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Recon-AD"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Recon_AD_offensive_tool_keyword = /\/Recon\-AD\.git/ nocase ascii wide
                        $string2_Recon_AD_offensive_tool_keyword = /\/Recon\-AD\-AllLocalGroups\.dll/ nocase ascii wide
                        $string3_Recon_AD_offensive_tool_keyword = /\/Recon\-AD\-Computers\.dll/ nocase ascii wide
                        $string4_Recon_AD_offensive_tool_keyword = /\/Recon\-AD\-Domain\.dll/ nocase ascii wide
                        $string5_Recon_AD_offensive_tool_keyword = /\/Recon\-AD\-Groups\.dll/ nocase ascii wide
                        $string6_Recon_AD_offensive_tool_keyword = /\/Recon\-AD\-LocalGroups\.dll/ nocase ascii wide
                        $string7_Recon_AD_offensive_tool_keyword = /\/Recon\-AD\-Users\.dll/ nocase ascii wide
                        $string8_Recon_AD_offensive_tool_keyword = /\[\!\]\sCould\snot\sexecute\squery\.\sCould\snot\sbind\sto\sLDAP\:\/\/rootDSE\./ nocase ascii wide
                        $string9_Recon_AD_offensive_tool_keyword = /\\Outflank\-Recon\-AD\\/ nocase ascii wide
                        $string10_Recon_AD_offensive_tool_keyword = /\\Recon\-AD\-AllLocalGroups\.dll/ nocase ascii wide
                        $string11_Recon_AD_offensive_tool_keyword = /\\Recon\-AD\-AllLocalGroups\.sln/ nocase ascii wide
                        $string12_Recon_AD_offensive_tool_keyword = /\\Recon\-AD\-AllLocalGroups\\/ nocase ascii wide
                        $string13_Recon_AD_offensive_tool_keyword = /\\Recon\-AD\-Computers\.dll/ nocase ascii wide
                        $string14_Recon_AD_offensive_tool_keyword = /\\Recon\-AD\-Computers\.sln/ nocase ascii wide
                        $string15_Recon_AD_offensive_tool_keyword = /\\Recon\-AD\-Computers\\/ nocase ascii wide
                        $string16_Recon_AD_offensive_tool_keyword = /\\Recon\-AD\-Domain\.dll/ nocase ascii wide
                        $string17_Recon_AD_offensive_tool_keyword = /\\Recon\-AD\-Domain\.sln/ nocase ascii wide
                        $string18_Recon_AD_offensive_tool_keyword = /\\Recon\-AD\-Domain\\/ nocase ascii wide
                        $string19_Recon_AD_offensive_tool_keyword = /\\Recon\-AD\-Groups\.dll/ nocase ascii wide
                        $string20_Recon_AD_offensive_tool_keyword = /\\Recon\-AD\-Groups\.sln/ nocase ascii wide
                        $string21_Recon_AD_offensive_tool_keyword = /\\Recon\-AD\-LocalGroups\.dll/ nocase ascii wide
                        $string22_Recon_AD_offensive_tool_keyword = /\\Recon\-AD\-LocalGroups\.sln/ nocase ascii wide
                        $string23_Recon_AD_offensive_tool_keyword = /\\Recon\-AD\-LocalGroups\\/ nocase ascii wide
                        $string24_Recon_AD_offensive_tool_keyword = /\\Recon\-AD\-master/ nocase ascii wide
                        $string25_Recon_AD_offensive_tool_keyword = /\\Recon\-AD\-SPNs\.sln/ nocase ascii wide
                        $string26_Recon_AD_offensive_tool_keyword = /\\Recon\-AD\-SPNs\\/ nocase ascii wide
                        $string27_Recon_AD_offensive_tool_keyword = /\\Recon\-AD\-Users\.dll/ nocase ascii wide
                        $string28_Recon_AD_offensive_tool_keyword = /\\Recon\-AD\-Users\.sln/ nocase ascii wide
                        $string29_Recon_AD_offensive_tool_keyword = /\\ReflectiveDll\.cpp/ nocase ascii wide
                        $string30_Recon_AD_offensive_tool_keyword = /\\ReflectiveLoader\.cpp/ nocase ascii wide
                        $string31_Recon_AD_offensive_tool_keyword = /\\Src\\Recon\-AD\-Groups\\/ nocase ascii wide
                        $string32_Recon_AD_offensive_tool_keyword = /\\Src\\Recon\-AD\-Users\\/ nocase ascii wide
                        $string33_Recon_AD_offensive_tool_keyword = "_REFLECTIVEDLLINJECTION_REFLECTIVEDLLINJECTION_H" nocase ascii wide
                        $string34_Recon_AD_offensive_tool_keyword = "D30C9D6B-1F45-47BD-825B-389FE8CC9069" nocase ascii wide
                        $string35_Recon_AD_offensive_tool_keyword = "outflanknl/Recon-AD" nocase ascii wide
                        $string36_Recon_AD_offensive_tool_keyword = "Recon-AD-Computers All" nocase ascii wide
                        $string37_Recon_AD_offensive_tool_keyword = "Recon-AD-Groups All" nocase ascii wide
                        $string38_Recon_AD_offensive_tool_keyword = "Recon-AD-Users All" nocase ascii wide
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