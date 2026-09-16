rule rule_Shoggoth_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Shoggoth' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Shoggoth"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Shoggoth_offensive_tool_keyword = " --coff-arg " nocase ascii wide
                        $string2_Shoggoth_offensive_tool_keyword = /\sCOFFLoader\.exe/ nocase ascii wide
                        $string3_Shoggoth_offensive_tool_keyword = /\sShoggoth\.exe/ nocase ascii wide
                        $string4_Shoggoth_offensive_tool_keyword = /\#include\s\\"ShoggothEngine\.h\\"/ nocase ascii wide
                        $string5_Shoggoth_offensive_tool_keyword = /\/beacon_generate\.py/ nocase ascii wide
                        $string6_Shoggoth_offensive_tool_keyword = /\/COFFLoader\.exe/ nocase ascii wide
                        $string7_Shoggoth_offensive_tool_keyword = /\/Shoggoth\.exe/ nocase ascii wide
                        $string8_Shoggoth_offensive_tool_keyword = /\/Shoggoth\.git/ nocase ascii wide
                        $string9_Shoggoth_offensive_tool_keyword = /\[\+\]\sCOFF\sLoader\smode\sis\sselected\!/ nocase ascii wide
                        $string10_Shoggoth_offensive_tool_keyword = /\[\+\]\sPE\sLoader\smode\sis\sselected\!/ nocase ascii wide
                        $string11_Shoggoth_offensive_tool_keyword = /\[\+\]\sPolymorphic\sencryption/ nocase ascii wide
                        $string12_Shoggoth_offensive_tool_keyword = /\[\+\]\sShoggoth\sengine\sis\sinitiated\!/ nocase ascii wide
                        $string13_Shoggoth_offensive_tool_keyword = /\\\\stub\\\\COFFLoader\.bin/ nocase ascii wide
                        $string14_Shoggoth_offensive_tool_keyword = /\\COFFLoader\.exe/ nocase ascii wide
                        $string15_Shoggoth_offensive_tool_keyword = /\\DumpNParse\.exe/ nocase ascii wide
                        $string16_Shoggoth_offensive_tool_keyword = /\\Shoggoth\.exe/ nocase ascii wide
                        $string17_Shoggoth_offensive_tool_keyword = /\\Shoggoth\.pptx/ nocase ascii wide
                        $string18_Shoggoth_offensive_tool_keyword = /\\Shoggoth\.sln/ nocase ascii wide
                        $string19_Shoggoth_offensive_tool_keyword = /\\ShoggothEngine\.cpp/ nocase ascii wide
                        $string20_Shoggoth_offensive_tool_keyword = "1bc3fc0ecdae8f404c33942914e6f442ea91400bdea77322b318ab576d4050a9" nocase ascii wide
                        $string21_Shoggoth_offensive_tool_keyword = "44D5BE95-F34D-4CC5-846F-C7758943B8FA" nocase ascii wide
                        $string22_Shoggoth_offensive_tool_keyword = "9cbbb2ac103af9b7940ec72a8e430427d86f5099f7a537e4fe2b72d69e05bdfd" nocase ascii wide
                        $string23_Shoggoth_offensive_tool_keyword = "'B','e','a','c','o','n'" nocase ascii wide
                        $string24_Shoggoth_offensive_tool_keyword = /bin\/PELoader\.exe/ nocase ascii wide
                        $string25_Shoggoth_offensive_tool_keyword = "d67630a3210bfcdd4b2fa2d48cdcdba0034710fd5ead616d9d5e4ce38e3c9809" nocase ascii wide
                        $string26_Shoggoth_offensive_tool_keyword = "frkngksl/Shoggoth" nocase ascii wide
                        $string27_Shoggoth_offensive_tool_keyword = "Shoggoth doesn't support x86 PE yet" nocase ascii wide
                        $string28_Shoggoth_offensive_tool_keyword = /ShoggothPolyEngine\(/ nocase ascii wide
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