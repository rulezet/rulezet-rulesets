rule rule_Kematian_Stealer_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Kematian Stealer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Kematian Stealer"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Kematian_Stealer_offensive_tool_keyword = /\sdefender\-exclusions\.ps1/ nocase ascii wide
                        $string2_Kematian_Stealer_offensive_tool_keyword = /\sencrypthub_steal\.ps1/ nocase ascii wide
                        $string3_Kematian_Stealer_offensive_tool_keyword = " EncryptHub-WINRAR-" nocase ascii wide
                        $string4_Kematian_Stealer_offensive_tool_keyword = /\$ransomNoteBase64/ nocase ascii wide
                        $string5_Kematian_Stealer_offensive_tool_keyword = /\/defender\-exclusions\.ps1/ nocase ascii wide
                        $string6_Kematian_Stealer_offensive_tool_keyword = /\/getChatAdministrators\?chat_id\=1002168553106/ nocase ascii wide
                        $string7_Kematian_Stealer_offensive_tool_keyword = /\/hvnc\/ngrok\.zip/ nocase ascii wide
                        $string8_Kematian_Stealer_offensive_tool_keyword = /\/kematian\.exe/ nocase ascii wide
                        $string9_Kematian_Stealer_offensive_tool_keyword = /\/worm\/inject\.ps1/ nocase ascii wide
                        $string10_Kematian_Stealer_offensive_tool_keyword = /\[STEALER\]\sBypass\sFinished/ nocase ascii wide
                        $string11_Kematian_Stealer_offensive_tool_keyword = /\\AppData\\Roaming\\Kematian/ nocase ascii wide
                        $string12_Kematian_Stealer_offensive_tool_keyword = /\\defender\-exclusions\.ps1/ nocase ascii wide
                        $string13_Kematian_Stealer_offensive_tool_keyword = /\\encrypthub_steal\.ps1/ nocase ascii wide
                        $string14_Kematian_Stealer_offensive_tool_keyword = /\\kematian\.exe/ nocase ascii wide
                        $string15_Kematian_Stealer_offensive_tool_keyword = /\\Kematian\\.{0,1000}Browser\sData/ nocase ascii wide
                        $string16_Kematian_Stealer_offensive_tool_keyword = /\\Kematian\\.{0,1000}Crypto\sWallets/ nocase ascii wide
                        $string17_Kematian_Stealer_offensive_tool_keyword = /\\Kematian\\.{0,1000}Important\sFiles/ nocase ascii wide
                        $string18_Kematian_Stealer_offensive_tool_keyword = /\\Kematian\\.{0,1000}Password\sManagers/ nocase ascii wide
                        $string19_Kematian_Stealer_offensive_tool_keyword = /\\Kematian\-Stealer\\/ nocase ascii wide
                        $string20_Kematian_Stealer_offensive_tool_keyword = /\\Users\\Public\\ngrok\.exe/ nocase ascii wide
                        $string21_Kematian_Stealer_offensive_tool_keyword = /\\Users\\Public\\server\.exe/ nocase ascii wide
                        $string22_Kematian_Stealer_offensive_tool_keyword = /\\WIFIPasswords\.txt/ nocase ascii wide
                        $string23_Kematian_Stealer_offensive_tool_keyword = /\\WinSCP\-sessions\.txt/ nocase ascii wide
                        $string24_Kematian_Stealer_offensive_tool_keyword = "078682e4de2e678702911508629fc3e0f293628720e67506340155091ce06ac5" nocase ascii wide
                        $string25_Kematian_Stealer_offensive_tool_keyword = "23b63ec6ec2a3d5addcf3d67c8ce01f913f5eaf3a77159606c6d28deff2c8d6e" nocase ascii wide
                        $string26_Kematian_Stealer_offensive_tool_keyword = "2dd2927d0f421a78f9289bee0e47449780a13ff7686a9d29c6afb0fec4c22576" nocase ascii wide
                        $string27_Kematian_Stealer_offensive_tool_keyword = "4192844c08997d6e198c0511821d0b6cdf8c87aa94cb0b2cd249c114e2c75bb6" nocase ascii wide
                        $string28_Kematian_Stealer_offensive_tool_keyword = "54584005fc341d7306b10709e9daf7ab60fcb9c782b7c81aa59c667d41d065bc" nocase ascii wide
                        $string29_Kematian_Stealer_offensive_tool_keyword = "7484009227:AAEvngzrIKFNFdfSqECzWAqbnB5IXk8pjVo" nocase ascii wide
                        $string30_Kematian_Stealer_offensive_tool_keyword = "9f946bd0783019a56d2a6de29dd7a2ae1a2b62239396a99eca83b17e4010fc0d" nocase ascii wide
                        $string31_Kematian_Stealer_offensive_tool_keyword = "b4ef4d10245cb81ac244e6fb545cc76a5fad1ac79eedbcec69b932765d5f29d8" nocase ascii wide
                        $string32_Kematian_Stealer_offensive_tool_keyword = "battle_net_stealer" nocase ascii wide
                        $string33_Kematian_Stealer_offensive_tool_keyword = "cb4406bc759bd471ac86d80678abd6dcec4934d8db7d92123ebd5960330699cf" nocase ascii wide
                        $string34_Kematian_Stealer_offensive_tool_keyword = "cfafc9b2d6cbc65769074bab296c5fbacc676d298f7391a3ff787307eb1cbce0" nocase ascii wide
                        $string35_Kematian_Stealer_offensive_tool_keyword = "d08e48fbfffffa54fb689d612cfa21a1a0e906ade2bca23bd12f89ce827bc0df" nocase ascii wide
                        $string36_Kematian_Stealer_offensive_tool_keyword = "da8ea1b2c9f697d582cbcf8ef9f61ecdfd4105643cc7da7b026c5333e4b6be58" nocase ascii wide
                        $string37_Kematian_Stealer_offensive_tool_keyword = "DecryptWinSCPPassword" nocase ascii wide
                        $string38_Kematian_Stealer_offensive_tool_keyword = /echo\s\%cmdcmdline\%\s\|\sfind\s\/i\s\\"\%\~f0\\"\>nul\s\|\|\sexit\s\/b\s1/
                        $string39_Kematian_Stealer_offensive_tool_keyword = "encrypthub_asseq2QSsxzc" nocase ascii wide
                        $string40_Kematian_Stealer_offensive_tool_keyword = "epicgames_stealer" nocase ascii wide
                        $string41_Kematian_Stealer_offensive_tool_keyword = /\-ExecutionPolicy\sBypass\s\-WindowStyle\sHidden\s\-Command\s\&\s\{taskkill\s\/f\s\/im\smmc\.exe/ nocase ascii wide
                        $string42_Kematian_Stealer_offensive_tool_keyword = "filezilla_stealer" nocase ascii wide
                        $string43_Kematian_Stealer_offensive_tool_keyword = "function KematianLoader" nocase ascii wide
                        $string44_Kematian_Stealer_offensive_tool_keyword = "Get-InstalledAV " nocase ascii wide
                        $string45_Kematian_Stealer_offensive_tool_keyword = /https\:\/\/mainstream\.ngrok\.app\/\?method\=UploadFile\&filename\=/ nocase ascii wide
                        $string46_Kematian_Stealer_offensive_tool_keyword = /https\:\/\/ratte\.ngrok\.app\/main\/mainer/ nocase ascii wide
                        $string47_Kematian_Stealer_offensive_tool_keyword = /https\:\/\/t\.me\/encrypthub/ nocase ascii wide
                        $string48_Kematian_Stealer_offensive_tool_keyword = /https\:\/\/www\.win\-rar\.co\/panel\// nocase ascii wide
                        $string49_Kematian_Stealer_offensive_tool_keyword = /Invoke\-WebRequest\s\-Uri\s\\"http\:\/\/ip\-api\.com\/line\/\?/ nocase ascii wide
                        $string50_Kematian_Stealer_offensive_tool_keyword = "JGtlbWF0aWFuLlNldFZhbHVlKCRudWxsLCR0cnVlKQ==" nocase ascii wide
                        $string51_Kematian_Stealer_offensive_tool_keyword = "KioqUkFOU09NIE5PVEUqKgoKWW91ciBmaWxlcyBoYXZlIGJlZW4gZW5jcnlwdGVkLgoKQWxsIHlvdXIgaW1wb3J0YW50IGZpbGVzLCBpbmNsdWRpbm" nocase ascii wide
                        $string52_Kematian_Stealer_offensive_tool_keyword = /livevnc\.ngrok\.app/ nocase ascii wide
                        $string53_Kematian_Stealer_offensive_tool_keyword = /mshta\.exe\svbscript\:createobject\(\`\\"wscript\.shell\`\\"\)\.run\(\`\\"powershell\s/ nocase ascii wide
                        $string54_Kematian_Stealer_offensive_tool_keyword = "New-NetFirewallRule -DisplayName \"KematianC2\" " nocase ascii wide
                        $string55_Kematian_Stealer_offensive_tool_keyword = "openvpn_stealer" nocase ascii wide
                        $string56_Kematian_Stealer_offensive_tool_keyword = "Pirate-Devs/Kematian" nocase ascii wide
                        $string57_Kematian_Stealer_offensive_tool_keyword = "protonvpnstealer" nocase ascii wide
                        $string58_Kematian_Stealer_offensive_tool_keyword = /Remove\-Item\s\(Get\-PSreadlineOption\)\.HistorySavePath\s\-Force\s\-ErrorAction\sSilentlyContinue/ nocase ascii wide
                        $string59_Kematian_Stealer_offensive_tool_keyword = "sap3r-encrypthub/encrypthub" nocase ascii wide
                        $string60_Kematian_Stealer_offensive_tool_keyword = "Send-TelegramMessage -message " nocase ascii wide
                        $string61_Kematian_Stealer_offensive_tool_keyword = /\'Sil\'\+\'ent\'\+\'l\'\+\'yContinu\'\+\'e\'/ nocase ascii wide
                        $string62_Kematian_Stealer_offensive_tool_keyword = "surfsharkvpnstealer" nocase ascii wide
                        $string63_Kematian_Stealer_offensive_tool_keyword = "UmVkIFRlYW1pbmcgYW5kIE9mZmVuc2l2ZSBTZWN1cml0eSAg" nocase ascii wide
                        $string64_Kematian_Stealer_offensive_tool_keyword = "UmVtb3ZlLUl0ZW0gKEdldC1QU3JlYWRsaW5lT3B0aW9uKS5IaXN0b3J5U2F2ZVBhdGggLUZvcmNlIC1FcnJvckFjdGlvbiBTaWxlbnRseUNvbnRpbnVl" nocase ascii wide

    condition:
        any of them
}