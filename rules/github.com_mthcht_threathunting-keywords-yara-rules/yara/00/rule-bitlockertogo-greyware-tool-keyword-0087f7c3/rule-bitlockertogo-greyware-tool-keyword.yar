rule rule_BitLockerToGo_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'BitLockerToGo' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BitLockerToGo"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_BitLockerToGo_greyware_tool_keyword = /\/BitLockerToGo\.exe/ nocase ascii wide
                        $string2_BitLockerToGo_greyware_tool_keyword = /\\Temp\\BitLockerToGo/ nocase ascii wide
                        $string3_BitLockerToGo_greyware_tool_keyword = /BitLockerToGo.{0,100}\.kdbx/ nocase ascii wide
                        $string4_BitLockerToGo_greyware_tool_keyword = /BitLockerToGo.{0,100}\\Network\\Cookies/ nocase ascii wide
                        $string5_BitLockerToGo_greyware_tool_keyword = /BitLockerToGo.{0,100}360Browser/ nocase ascii wide
                        $string6_BitLockerToGo_greyware_tool_keyword = /BitLockerToGo.{0,100}Anydesk/ nocase ascii wide
                        $string7_BitLockerToGo_greyware_tool_keyword = /BitLockerToGo.{0,100}Binance/ nocase ascii wide
                        $string8_BitLockerToGo_greyware_tool_keyword = /BitLockerToGo.{0,100}Bitcoin/ nocase ascii wide
                        $string9_BitLockerToGo_greyware_tool_keyword = /BitLockerToGo.{0,100}BraveSoftware/ nocase ascii wide
                        $string10_BitLockerToGo_greyware_tool_keyword = /BitLockerToGo.{0,100}CocCoc/ nocase ascii wide
                        $string11_BitLockerToGo_greyware_tool_keyword = /BitLockerToGo.{0,100}Coinomi/ nocase ascii wide
                        $string12_BitLockerToGo_greyware_tool_keyword = /BitLockerToGo.{0,100}ElectronCash/ nocase ascii wide
                        $string13_BitLockerToGo_greyware_tool_keyword = /BitLockerToGo.{0,100}Electrum/ nocase ascii wide
                        $string14_BitLockerToGo_greyware_tool_keyword = /BitLockerToGo.{0,100}Electrum/ nocase ascii wide
                        $string15_BitLockerToGo_greyware_tool_keyword = /BitLockerToGo.{0,100}Electrum/ nocase ascii wide
                        $string16_BitLockerToGo_greyware_tool_keyword = /BitLockerToGo.{0,100}Electrum/ nocase ascii wide
                        $string17_BitLockerToGo_greyware_tool_keyword = /BitLockerToGo.{0,100}Epic\sPrivacy\sBrowser/ nocase ascii wide
                        $string18_BitLockerToGo_greyware_tool_keyword = /BitLockerToGo.{0,100}Ethereum/ nocase ascii wide
                        $string19_BitLockerToGo_greyware_tool_keyword = /BitLockerToGo.{0,100}Exodus/ nocase ascii wide
                        $string20_BitLockerToGo_greyware_tool_keyword = /BitLockerToGo.{0,100}Filezilla/ nocase ascii wide
                        $string21_BitLockerToGo_greyware_tool_keyword = /BitLockerToGo.{0,100}Ledger/ nocase ascii wide
                        $string22_BitLockerToGo_greyware_tool_keyword = /BitLockerToGo.{0,100}MailBird/ nocase ascii wide
                        $string23_BitLockerToGo_greyware_tool_keyword = /BitLockerToGo.{0,100}metamask/ nocase ascii wide
                        $string24_BitLockerToGo_greyware_tool_keyword = /BitLockerToGo.{0,100}telegram/ nocase ascii wide
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