rule rule_localxpose_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'localxpose' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "localxpose"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_localxpose_greyware_tool_keyword = /\.loclx\.io\:/ nocase ascii wide
                        $string2_localxpose_greyware_tool_keyword = /\/.{0,1000}\.loclx\.io/ nocase ascii wide
                        $string3_localxpose_greyware_tool_keyword = /\/loclx\.exe/ nocase ascii wide
                        $string4_localxpose_greyware_tool_keyword = /\/loclx\-windows\-amd64\.zip/ nocase ascii wide
                        $string5_localxpose_greyware_tool_keyword = /\\loclx\.exe/ nocase ascii wide
                        $string6_localxpose_greyware_tool_keyword = /\\loclx\-windows\-amd64\.zip/ nocase ascii wide
                        $string7_localxpose_greyware_tool_keyword = "17a9356024d2fa2ae8f327fc5babc10eb859e0c433e768cd03a50dd9c7880601" nocase ascii wide
                        $string8_localxpose_greyware_tool_keyword = "33ab2fa30777211450e30c21c45803cdf076cb991f05691bd60aef97a8183e04" nocase ascii wide
                        $string9_localxpose_greyware_tool_keyword = /api\.localxpose\.io/ nocase ascii wide
                        $string10_localxpose_greyware_tool_keyword = "brew install --cask localxpose" nocase ascii wide
                        $string11_localxpose_greyware_tool_keyword = "cd1978742a4afdbaaa15bf712d5c90bef4144caa99024df98f6a9ad58043ae85" nocase ascii wide
                        $string12_localxpose_greyware_tool_keyword = "choco install localxpose" nocase ascii wide
                        $string13_localxpose_greyware_tool_keyword = /https\:\/\/localxpose\.io\/download/ nocase ascii wide
                        $string14_localxpose_greyware_tool_keyword = "localxpose/localxpose" nocase ascii wide
                        $string15_localxpose_greyware_tool_keyword = "loclx tunnel config " nocase ascii wide
                        $string16_localxpose_greyware_tool_keyword = "loclx tunnel http " nocase ascii wide
                        $string17_localxpose_greyware_tool_keyword = "loclx tunnel tcp " nocase ascii wide
                        $string18_localxpose_greyware_tool_keyword = "loclx tunnel tls " nocase ascii wide
                        $string19_localxpose_greyware_tool_keyword = "loclx tunnel udp " nocase ascii wide
                        $string20_localxpose_greyware_tool_keyword = /loclx\.exe\stunnel\shttp\s/ nocase ascii wide
                        $string21_localxpose_greyware_tool_keyword = /loclx\.exe\stunnel\stcp\s/ nocase ascii wide
                        $string22_localxpose_greyware_tool_keyword = /loclx\.exe\stunnel\stls\s/ nocase ascii wide
                        $string23_localxpose_greyware_tool_keyword = /loclx\.exe\stunnel\sudp\s/ nocase ascii wide
                        $string24_localxpose_greyware_tool_keyword = /loclx\-client\.s3\.amazonaws\.com/ nocase ascii wide
                        $string25_localxpose_greyware_tool_keyword = "npm install localxpose" nocase ascii wide
                        $string26_localxpose_greyware_tool_keyword = "snap install localxpose" nocase ascii wide
                        $string27_localxpose_greyware_tool_keyword = "yarn add localxpose" nocase ascii wide

    condition:
        any of them
}