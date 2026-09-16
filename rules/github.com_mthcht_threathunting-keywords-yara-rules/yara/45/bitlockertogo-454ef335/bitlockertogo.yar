rule BitLockerToGo
{
    meta:
        description = "Detection patterns for the tool 'BitLockerToGo' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BitLockerToGo"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\/BitLockerToGo\.exe/ nocase ascii wide
                        $string2 = /\\Temp\\BitLockerToGo/ nocase ascii wide
                        $string3 = /BitLockerToGo.{0,1000}\.kdbx/ nocase ascii wide
                        $string4 = /BitLockerToGo.{0,1000}\\Network\\Cookies/ nocase ascii wide
                        $string5 = /BitLockerToGo.{0,1000}360Browser/ nocase ascii wide
                        $string6 = /BitLockerToGo.{0,1000}Anydesk/ nocase ascii wide
                        $string7 = /BitLockerToGo.{0,1000}Binance/ nocase ascii wide
                        $string8 = /BitLockerToGo.{0,1000}Bitcoin/ nocase ascii wide
                        $string9 = /BitLockerToGo.{0,1000}BraveSoftware/ nocase ascii wide
                        $string10 = /BitLockerToGo.{0,1000}CocCoc/ nocase ascii wide
                        $string11 = /BitLockerToGo.{0,1000}Coinomi/ nocase ascii wide
                        $string12 = /BitLockerToGo.{0,1000}ElectronCash/ nocase ascii wide
                        $string13 = /BitLockerToGo.{0,1000}Electrum/ nocase ascii wide
                        $string14 = /BitLockerToGo.{0,1000}Electrum/ nocase ascii wide
                        $string15 = /BitLockerToGo.{0,1000}Electrum/ nocase ascii wide
                        $string16 = /BitLockerToGo.{0,1000}Electrum/ nocase ascii wide
                        $string17 = /BitLockerToGo.{0,1000}Epic\sPrivacy\sBrowser/ nocase ascii wide
                        $string18 = /BitLockerToGo.{0,1000}Ethereum/ nocase ascii wide
                        $string19 = /BitLockerToGo.{0,1000}Exodus/ nocase ascii wide
                        $string20 = /BitLockerToGo.{0,1000}Filezilla/ nocase ascii wide
                        $string21 = /BitLockerToGo.{0,1000}Ledger/ nocase ascii wide
                        $string22 = /BitLockerToGo.{0,1000}MailBird/ nocase ascii wide
                        $string23 = /BitLockerToGo.{0,1000}metamask/ nocase ascii wide
                        $string24 = /BitLockerToGo.{0,1000}telegram/ nocase ascii wide

    condition:
        any of them
}