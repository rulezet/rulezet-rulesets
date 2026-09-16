rule rule_zrok_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'zrok' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "zrok"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_zrok_greyware_tool_keyword = " admin create frontend sqJRAINSiB public " nocase ascii wide
                        $string2_zrok_greyware_tool_keyword = " -c rest_client_zrok -t" nocase ascii wide
                        $string3_zrok_greyware_tool_keyword = " -s rest_server_zrok -t" nocase ascii wide
                        $string4_zrok_greyware_tool_keyword = /\szrok\.listener/ nocase ascii wide
                        $string5_zrok_greyware_tool_keyword = /\$HOME\/\.zrok/ nocase ascii wide
                        $string6_zrok_greyware_tool_keyword = /\.in\.zrok\.io/ nocase ascii wide
                        $string7_zrok_greyware_tool_keyword = /\.share\.zrok\.io/ nocase ascii wide
                        $string8_zrok_greyware_tool_keyword = /\.zrok\.quigley\.com/ nocase ascii wide
                        $string9_zrok_greyware_tool_keyword = /\/\.zrok\/.{0,100}\.json/
                        $string10_zrok_greyware_tool_keyword = /\/\.zrok\:\/\.zrok/
                        $string11_zrok_greyware_tool_keyword = /\/\/\sNewHTTPClient\screates\sa\snew\szrok\sHTTP\sclient\./
                        $string12_zrok_greyware_tool_keyword = "/docker/compose/zrok-instance/"
                        $string13_zrok_greyware_tool_keyword = /\/etc\/zrok\.env/
                        $string14_zrok_greyware_tool_keyword = "/etc/zrok/"
                        $string15_zrok_greyware_tool_keyword = "/rest_client_zrok/"
                        $string16_zrok_greyware_tool_keyword = "/var/lib/zrok-"
                        $string17_zrok_greyware_tool_keyword = /\/zrok\.exe/ nocase ascii wide
                        $string18_zrok_greyware_tool_keyword = /\/zrok\.git/ nocase ascii wide
                        $string19_zrok_greyware_tool_keyword = /\/zrok\.zip/ nocase ascii wide
                        $string20_zrok_greyware_tool_keyword = "/zrok-amd64_darwin_amd64"
                        $string21_zrok_greyware_tool_keyword = "/zrok-arm64_darwin_arm64"
                        $string22_zrok_greyware_tool_keyword = /\/zrok\-controller\.log/
                        $string23_zrok_greyware_tool_keyword = "/zrok-docker/"
                        $string24_zrok_greyware_tool_keyword = /\/zrok\-frontend\.log/
                        $string25_zrok_greyware_tool_keyword = /\/zrok\-share\.env/
                        $string26_zrok_greyware_tool_keyword = /\\zrok\.exe/ nocase ascii wide
                        $string27_zrok_greyware_tool_keyword = /\\zrok\.zip/ nocase ascii wide
                        $string28_zrok_greyware_tool_keyword = /\\zrok\-controller\.log/ nocase ascii wide
                        $string29_zrok_greyware_tool_keyword = /\\zrok\-frontend\.log/ nocase ascii wide
                        $string30_zrok_greyware_tool_keyword = ">Welcome new zrok user!<" nocase ascii wide
                        $string31_zrok_greyware_tool_keyword = ">Welcome to zrok!<" nocase ascii wide
                        $string32_zrok_greyware_tool_keyword = ">zrok frontend health: ok<" nocase ascii wide
                        $string33_zrok_greyware_tool_keyword = ">zrok test endpoint<" nocase ascii wide
                        $string34_zrok_greyware_tool_keyword = "25e850edd1cb8707c9a18a0fcc610b831cce25203dff650ec7e781175d900df3" nocase ascii wide
                        $string35_zrok_greyware_tool_keyword = "4adeaf8287ac71363bb2c5ccd6b67b8c973f783702c18c444741875375772be1" nocase ascii wide
                        $string36_zrok_greyware_tool_keyword = "651caf1b8d81a445db65551955dda4aa7df88a0013a81fda506bdfcfe05611b0" nocase ascii wide
                        $string37_zrok_greyware_tool_keyword = "9af57a343f42da2250dd4499d6dcff61a7a6395eae77eaab0ddddbe544743116" nocase ascii wide
                        $string38_zrok_greyware_tool_keyword = "d5be8ba1112a210428cac87772b6d7902a9b9299b9a658d03ffbc52e9d125593" nocase ascii wide
                        $string39_zrok_greyware_tool_keyword = "def7512aaa595d7cad9b2e237a0ee99e778bbae0a30dd2eba75d099fc80f310f" nocase ascii wide
                        $string40_zrok_greyware_tool_keyword = /http.{0,100}api\.zrok\./ nocase ascii wide
                        $string41_zrok_greyware_tool_keyword = /http\:\/\/.{0,100}\.zrok\.io/ nocase ascii wide
                        $string42_zrok_greyware_tool_keyword = /http\:\/\/127\.0\.0\.1\:18080/ nocase ascii wide
                        $string43_zrok_greyware_tool_keyword = /http\:\/\/127\.0\.0\.1\:9191/ nocase ascii wide
                        $string44_zrok_greyware_tool_keyword = /https\:\/\/.{0,100}\.zrok\.io/ nocase ascii wide
                        $string45_zrok_greyware_tool_keyword = /https\:\/\/zrok\./ nocase ascii wide
                        $string46_zrok_greyware_tool_keyword = "openziti/zrok" nocase ascii wide
                        $string47_zrok_greyware_tool_keyword = "pastefrom b46p9j82z81f" nocase ascii wide
                        $string48_zrok_greyware_tool_keyword = /share\.zrok\.io/ nocase ascii wide
                        $string49_zrok_greyware_tool_keyword = /tags\.zrokShareToken\=/ nocase ascii wide
                        $string50_zrok_greyware_tool_keyword = "the zrok environment was successfully enabled" nocase ascii wide
                        $string51_zrok_greyware_tool_keyword = /zrockify_func\(/ nocase ascii wide
                        $string52_zrok_greyware_tool_keyword = "zrok admin bootstrap" nocase ascii wide
                        $string53_zrok_greyware_tool_keyword = "zrok configuration updated" nocase ascii wide
                        $string54_zrok_greyware_tool_keyword = "zrok environment disabled" nocase ascii wide
                        $string55_zrok_greyware_tool_keyword = "zrok share public " nocase ascii wide
                        $string56_zrok_greyware_tool_keyword = "zrok share reserved " nocase ascii wide
                        $string57_zrok_greyware_tool_keyword = "zrok test loop public" nocase ascii wide
                        $string58_zrok_greyware_tool_keyword = /zrok\.environment\.root/ nocase ascii wide
                        $string59_zrok_greyware_tool_keyword = /zrok\.environment\.root\.Load/ nocase ascii wide
                        $string60_zrok_greyware_tool_keyword = /zrok\.proxy\.v1/ nocase ascii wide
                        $string61_zrok_greyware_tool_keyword = /zrok\.share\.CreateShare\(/ nocase ascii wide
                        $string62_zrok_greyware_tool_keyword = /zrok_api\.configuration/ nocase ascii wide
                        $string63_zrok_greyware_tool_keyword = "ZROK_BACKEND_MODE" nocase ascii wide
                        $string64_zrok_greyware_tool_keyword = "ZROK_RESERVED_TOKEN" nocase ascii wide
                        $string65_zrok_greyware_tool_keyword = /zrok\-share\.service/ nocase ascii wide
                        $string66_zrok_greyware_tool_keyword = "zrokSvcId=" nocase ascii wide
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