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
                        $string3_BitLockerToGo_greyware_tool_keyword = /BitLockerToGo.{0,1000}\.kdbx/ nocase ascii wide
                        $string4_BitLockerToGo_greyware_tool_keyword = /BitLockerToGo.{0,1000}\\Network\\Cookies/ nocase ascii wide
                        $string5_BitLockerToGo_greyware_tool_keyword = /BitLockerToGo.{0,1000}360Browser/ nocase ascii wide
                        $string6_BitLockerToGo_greyware_tool_keyword = /BitLockerToGo.{0,1000}Anydesk/ nocase ascii wide
                        $string7_BitLockerToGo_greyware_tool_keyword = /BitLockerToGo.{0,1000}Binance/ nocase ascii wide
                        $string8_BitLockerToGo_greyware_tool_keyword = /BitLockerToGo.{0,1000}Bitcoin/ nocase ascii wide
                        $string9_BitLockerToGo_greyware_tool_keyword = /BitLockerToGo.{0,1000}BraveSoftware/ nocase ascii wide
                        $string10_BitLockerToGo_greyware_tool_keyword = /BitLockerToGo.{0,1000}CocCoc/ nocase ascii wide
                        $string11_BitLockerToGo_greyware_tool_keyword = /BitLockerToGo.{0,1000}Coinomi/ nocase ascii wide
                        $string12_BitLockerToGo_greyware_tool_keyword = /BitLockerToGo.{0,1000}ElectronCash/ nocase ascii wide
                        $string13_BitLockerToGo_greyware_tool_keyword = /BitLockerToGo.{0,1000}Electrum/ nocase ascii wide
                        $string14_BitLockerToGo_greyware_tool_keyword = /BitLockerToGo.{0,1000}Electrum/ nocase ascii wide
                        $string15_BitLockerToGo_greyware_tool_keyword = /BitLockerToGo.{0,1000}Electrum/ nocase ascii wide
                        $string16_BitLockerToGo_greyware_tool_keyword = /BitLockerToGo.{0,1000}Electrum/ nocase ascii wide
                        $string17_BitLockerToGo_greyware_tool_keyword = /BitLockerToGo.{0,1000}Epic\sPrivacy\sBrowser/ nocase ascii wide
                        $string18_BitLockerToGo_greyware_tool_keyword = /BitLockerToGo.{0,1000}Ethereum/ nocase ascii wide
                        $string19_BitLockerToGo_greyware_tool_keyword = /BitLockerToGo.{0,1000}Exodus/ nocase ascii wide
                        $string20_BitLockerToGo_greyware_tool_keyword = /BitLockerToGo.{0,1000}Filezilla/ nocase ascii wide
                        $string21_BitLockerToGo_greyware_tool_keyword = /BitLockerToGo.{0,1000}Ledger/ nocase ascii wide
                        $string22_BitLockerToGo_greyware_tool_keyword = /BitLockerToGo.{0,1000}MailBird/ nocase ascii wide
                        $string23_BitLockerToGo_greyware_tool_keyword = /BitLockerToGo.{0,1000}metamask/ nocase ascii wide
                        $string24_BitLockerToGo_greyware_tool_keyword = /BitLockerToGo.{0,1000}telegram/ nocase ascii wide

    condition:
        any of them
}