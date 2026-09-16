rule rule_RouterScan_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'RouterScan' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RouterScan"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_RouterScan_offensive_tool_keyword = "/pixiewps --"
                        $string2_RouterScan_offensive_tool_keyword = /\/pixiewps\/archive\/master\.zip/ nocase ascii wide
                        $string3_RouterScan_offensive_tool_keyword = /\/Routerscan\.7z/ nocase ascii wide
                        $string4_RouterScan_offensive_tool_keyword = /\/RouterScan\.exe/ nocase ascii wide
                        $string5_RouterScan_offensive_tool_keyword = /\/router\-scan\.git/ nocase ascii wide
                        $string6_RouterScan_offensive_tool_keyword = /\/RouterScan\.log/
                        $string7_RouterScan_offensive_tool_keyword = /\/wlanpass\.txt/
                        $string8_RouterScan_offensive_tool_keyword = /\\Routerscan\.7z/ nocase ascii wide
                        $string9_RouterScan_offensive_tool_keyword = /\\RouterScan\.exe/ nocase ascii wide
                        $string10_RouterScan_offensive_tool_keyword = /\\RouterScan\.log/ nocase ascii wide
                        $string11_RouterScan_offensive_tool_keyword = /\\wlanpass\.txt/ nocase ascii wide
                        $string12_RouterScan_offensive_tool_keyword = ">Router Scan by Stas'M<" nocase ascii wide
                        $string13_RouterScan_offensive_tool_keyword = "18229920a45130f00539405fecab500d8010ef93856e1c5bcabf5aa5532b3311" nocase ascii wide
                        $string14_RouterScan_offensive_tool_keyword = "49966f985d0d509cebebda87d56da72e6a94253adfb3252000dfff73fb207ff0" nocase ascii wide
                        $string15_RouterScan_offensive_tool_keyword = "b875051a6d584b37810ea48923af45e20d1367adfa94266bfe47a1a35d76b03a" nocase ascii wide
                        $string16_RouterScan_offensive_tool_keyword = "b91166d5623d4077003ae8527e9169092994f5c189c8a3820b32e204b4230578" nocase ascii wide
                        $string17_RouterScan_offensive_tool_keyword = "e97da4284459149541ef261a6de0bec7ef8a3d2d28d3384b7b256c089d524690" nocase ascii wide
                        $string18_RouterScan_offensive_tool_keyword = "f61ebc6c8692c620a57b7b167206e74131df5e4d651ae55713392bde4b0e8b9f" nocase ascii wide
                        $string19_RouterScan_offensive_tool_keyword = /http\:\/\/0x0\.st\/tm/ nocase ascii wide
                        $string20_RouterScan_offensive_tool_keyword = /http\:\/\/3wifi\.stascorp\.com\/3wifi\.php/ nocase ascii wide
                        $string21_RouterScan_offensive_tool_keyword = "mustafashykh/router-scan" nocase ascii wide
                        $string22_RouterScan_offensive_tool_keyword = "pixiewps -e" nocase ascii wide
                        $string23_RouterScan_offensive_tool_keyword = /Upload\.Password\=antichat/ nocase ascii wide

    condition:
        any of them
}