rule rule_SharpDPAPI_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpDPAPI' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpDPAPI"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SharpDPAPI_offensive_tool_keyword = /\sbackupkey.{0,100}\s\/server\:.{0,100}\s\/file.{0,100}\.pvk/ nocase ascii wide
                        $string2_SharpDPAPI_offensive_tool_keyword = /\sblob\s\/target\:.{0,100}\.bin.{0,100}\s\/pvk\:/ nocase ascii wide
                        $string3_SharpDPAPI_offensive_tool_keyword = /\sblob\s\/target\:.{0,100}\.bin.{0,100}\s\/unprotect/ nocase ascii wide
                        $string4_SharpDPAPI_offensive_tool_keyword = " credentials /pvk:" nocase ascii wide
                        $string5_SharpDPAPI_offensive_tool_keyword = " keepass /unprotect" nocase ascii wide
                        $string6_SharpDPAPI_offensive_tool_keyword = /\sps\s\/target\:.{0,100}\.xml\s\/unprotect/ nocase ascii wide
                        $string7_SharpDPAPI_offensive_tool_keyword = /\svaults\s\/target\:.{0,100}\s\/pvk\:/ nocase ascii wide
                        $string8_SharpDPAPI_offensive_tool_keyword = /\.exe\s\scertificates\s\/pvk\:.{0,100}\.pvk/ nocase ascii wide
                        $string9_SharpDPAPI_offensive_tool_keyword = /\.exe\s\skeepass\s\/unprotect/ nocase ascii wide
                        $string10_SharpDPAPI_offensive_tool_keyword = /\.exe\sbackupkey\s\/nowrap\s.{0,100}\.pvk/ nocase ascii wide
                        $string11_SharpDPAPI_offensive_tool_keyword = /\.exe\sbackupkey\s\/server\:/ nocase ascii wide
                        $string12_SharpDPAPI_offensive_tool_keyword = /\.exe\sblob\s\/target\:C\:\\Temp\\/ nocase ascii wide
                        $string13_SharpDPAPI_offensive_tool_keyword = /\.exe\scertificates\s\/mkfile\:.{0,100}\.txt/ nocase ascii wide
                        $string14_SharpDPAPI_offensive_tool_keyword = /\.exe\scertificates\s\/unprotect/ nocase ascii wide
                        $string15_SharpDPAPI_offensive_tool_keyword = /\.exe\scredentials\s\/pvk\:.{0,100}\.pvk/ nocase ascii wide
                        $string16_SharpDPAPI_offensive_tool_keyword = /\.exe\smachinemasterkeys/ nocase ascii wide
                        $string17_SharpDPAPI_offensive_tool_keyword = /\.exe\smachinetriage/ nocase ascii wide
                        $string18_SharpDPAPI_offensive_tool_keyword = /\.exe\smachinevaults/ nocase ascii wide
                        $string19_SharpDPAPI_offensive_tool_keyword = /\.exe\smasterkeys\s\/hashes/ nocase ascii wide
                        $string20_SharpDPAPI_offensive_tool_keyword = /\.exe\smasterkeys\s\/hashes/ nocase ascii wide
                        $string21_SharpDPAPI_offensive_tool_keyword = /\.exe\smasterkeys\s\/pvk\:/ nocase ascii wide
                        $string22_SharpDPAPI_offensive_tool_keyword = /\.exe\sps\s\/target\:C\:\\Temp\\.{0,100}\s\/unprotect/ nocase ascii wide
                        $string23_SharpDPAPI_offensive_tool_keyword = /\.exe\srdg\s\/unprotect/ nocase ascii wide
                        $string24_SharpDPAPI_offensive_tool_keyword = /\.exe\striage\s\/password\:/ nocase ascii wide
                        $string25_SharpDPAPI_offensive_tool_keyword = /\/SharpDPAPI\.exe/ nocase ascii wide
                        $string26_SharpDPAPI_offensive_tool_keyword = /\/SharpDPAPI\.git/ nocase ascii wide
                        $string27_SharpDPAPI_offensive_tool_keyword = /\[SharpDPAPI\.Program\]\:\:Main\(\\"machinemasterkeys\\"\)/ nocase ascii wide
                        $string28_SharpDPAPI_offensive_tool_keyword = /\[X\]\sMust\sbe\selevated\sto\striage\sSYSTEM\scredentials\!/ nocase ascii wide
                        $string29_SharpDPAPI_offensive_tool_keyword = /\[X\]\sMust\sbe\selevated\sto\striage\sSYSTEM\smasterkeys\!/ nocase ascii wide
                        $string30_SharpDPAPI_offensive_tool_keyword = /\[X\]\sMust\sbe\selevated\sto\striage\sSYSTEM\svaults\!/ nocase ascii wide
                        $string31_SharpDPAPI_offensive_tool_keyword = /\\Commands\\Machinecredentials\.cs/ nocase ascii wide
                        $string32_SharpDPAPI_offensive_tool_keyword = /\\SharpDPAPI\.exe/ nocase ascii wide
                        $string33_SharpDPAPI_offensive_tool_keyword = /\\SharpDPAPI\\/ nocase ascii wide
                        $string34_SharpDPAPI_offensive_tool_keyword = /\]\sWill\sdecrypt\suser\smasterkeys\swith\sNTLM\shash\:\s/ nocase ascii wide
                        $string35_SharpDPAPI_offensive_tool_keyword = ">SharpDPAPI<" nocase ascii wide
                        $string36_SharpDPAPI_offensive_tool_keyword = "2F00A05B-263D-4FCC-846B-DA82BD684603" nocase ascii wide
                        $string37_SharpDPAPI_offensive_tool_keyword = "5d975e81c68574849bb0fec4c6d2116a4ba7dd58bdd1710463ab75d9a8054bc3" nocase ascii wide
                        $string38_SharpDPAPI_offensive_tool_keyword = "5F026C27-F8E6-4052-B231-8451C6A73838" nocase ascii wide
                        $string39_SharpDPAPI_offensive_tool_keyword = "d907d7686b725441db1deb645a7079ca79f4dd1d8a18ca4b2bb98c12622603ef" nocase ascii wide
                        $string40_SharpDPAPI_offensive_tool_keyword = "GhostPack/SharpDPAPI" nocase ascii wide
                        $string41_SharpDPAPI_offensive_tool_keyword = /MakeMeEnterpriseAdmin\.ps1/ nocase ascii wide
                        $string42_SharpDPAPI_offensive_tool_keyword = /SharpChrome.{0,100}\sbackupkey\s.{0,100}\.pvk/ nocase ascii wide
                        $string43_SharpDPAPI_offensive_tool_keyword = "SharpDPAPI backupkey" nocase ascii wide
                        $string44_SharpDPAPI_offensive_tool_keyword = "SharpDPAPI backupkey" nocase ascii wide
                        $string45_SharpDPAPI_offensive_tool_keyword = "SharpDPAPI completed in " nocase ascii wide
                        $string46_SharpDPAPI_offensive_tool_keyword = /SharpDPAPI.{0,100}\scredentias\s/ nocase ascii wide
                        $string47_SharpDPAPI_offensive_tool_keyword = /SharpDPAPI.{0,100}\svaults\s/ nocase ascii wide
                        $string48_SharpDPAPI_offensive_tool_keyword = /SharpDPAPI\.csproj/ nocase ascii wide
                        $string49_SharpDPAPI_offensive_tool_keyword = /SharpDPAPI\.Domain/ nocase ascii wide
                        $string50_SharpDPAPI_offensive_tool_keyword = /SharpDPAPI\.exe/ nocase ascii wide
                        $string51_SharpDPAPI_offensive_tool_keyword = /SharpDPAPI\.Helpers\./ nocase ascii wide
                        $string52_SharpDPAPI_offensive_tool_keyword = /SharpDPAPI\.ps1/ nocase ascii wide
                        $string53_SharpDPAPI_offensive_tool_keyword = /SharpDPAPI\.sln/ nocase ascii wide
                        $string54_SharpDPAPI_offensive_tool_keyword = /SharpDPAPI\.txt/ nocase ascii wide
                        $string55_SharpDPAPI_offensive_tool_keyword = "SharpDPAPI-master" nocase ascii wide
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