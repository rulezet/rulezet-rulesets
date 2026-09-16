rule Kematian_Stealer
{
    meta:
        description = "Detection patterns for the tool 'Kematian Stealer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Kematian Stealer"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sdefender\-exclusions\.ps1/ nocase ascii wide
                        $string2 = /\sencrypthub_steal\.ps1/ nocase ascii wide
                        $string3 = " EncryptHub-WINRAR-" nocase ascii wide
                        $string4 = /\$ransomNoteBase64/ nocase ascii wide
                        $string5 = /\/defender\-exclusions\.ps1/ nocase ascii wide
                        $string6 = /\/getChatAdministrators\?chat_id\=1002168553106/ nocase ascii wide
                        $string7 = /\/hvnc\/ngrok\.zip/ nocase ascii wide
                        $string8 = /\/kematian\.exe/ nocase ascii wide
                        $string9 = /\/worm\/inject\.ps1/ nocase ascii wide
                        $string10 = /\[STEALER\]\sBypass\sFinished/ nocase ascii wide
                        $string11 = /\\AppData\\Roaming\\Kematian/ nocase ascii wide
                        $string12 = /\\defender\-exclusions\.ps1/ nocase ascii wide
                        $string13 = /\\encrypthub_steal\.ps1/ nocase ascii wide
                        $string14 = /\\kematian\.exe/ nocase ascii wide
                        $string15 = /\\Kematian\\.{0,1000}Browser\sData/ nocase ascii wide
                        $string16 = /\\Kematian\\.{0,1000}Crypto\sWallets/ nocase ascii wide
                        $string17 = /\\Kematian\\.{0,1000}Important\sFiles/ nocase ascii wide
                        $string18 = /\\Kematian\\.{0,1000}Password\sManagers/ nocase ascii wide
                        $string19 = /\\Kematian\-Stealer\\/ nocase ascii wide
                        $string20 = /\\Users\\Public\\ngrok\.exe/ nocase ascii wide
                        $string21 = /\\Users\\Public\\server\.exe/ nocase ascii wide
                        $string22 = /\\WIFIPasswords\.txt/ nocase ascii wide
                        $string23 = /\\WinSCP\-sessions\.txt/ nocase ascii wide
                        $string24 = "078682e4de2e678702911508629fc3e0f293628720e67506340155091ce06ac5" nocase ascii wide
                        $string25 = "23b63ec6ec2a3d5addcf3d67c8ce01f913f5eaf3a77159606c6d28deff2c8d6e" nocase ascii wide
                        $string26 = "2dd2927d0f421a78f9289bee0e47449780a13ff7686a9d29c6afb0fec4c22576" nocase ascii wide
                        $string27 = "4192844c08997d6e198c0511821d0b6cdf8c87aa94cb0b2cd249c114e2c75bb6" nocase ascii wide
                        $string28 = "54584005fc341d7306b10709e9daf7ab60fcb9c782b7c81aa59c667d41d065bc" nocase ascii wide
                        $string29 = "7484009227:AAEvngzrIKFNFdfSqECzWAqbnB5IXk8pjVo" nocase ascii wide
                        $string30 = "9f946bd0783019a56d2a6de29dd7a2ae1a2b62239396a99eca83b17e4010fc0d" nocase ascii wide
                        $string31 = "b4ef4d10245cb81ac244e6fb545cc76a5fad1ac79eedbcec69b932765d5f29d8" nocase ascii wide
                        $string32 = "battle_net_stealer" nocase ascii wide
                        $string33 = "cb4406bc759bd471ac86d80678abd6dcec4934d8db7d92123ebd5960330699cf" nocase ascii wide
                        $string34 = "cfafc9b2d6cbc65769074bab296c5fbacc676d298f7391a3ff787307eb1cbce0" nocase ascii wide
                        $string35 = "d08e48fbfffffa54fb689d612cfa21a1a0e906ade2bca23bd12f89ce827bc0df" nocase ascii wide
                        $string36 = "da8ea1b2c9f697d582cbcf8ef9f61ecdfd4105643cc7da7b026c5333e4b6be58" nocase ascii wide
                        $string37 = "DecryptWinSCPPassword" nocase ascii wide
                        $string38 = /echo\s\%cmdcmdline\%\s\|\sfind\s\/i\s\\"\%\~f0\\"\>nul\s\|\|\sexit\s\/b\s1/
                        $string39 = "encrypthub_asseq2QSsxzc" nocase ascii wide
                        $string40 = "epicgames_stealer" nocase ascii wide
                        $string41 = /\-ExecutionPolicy\sBypass\s\-WindowStyle\sHidden\s\-Command\s\&\s\{taskkill\s\/f\s\/im\smmc\.exe/ nocase ascii wide
                        $string42 = "filezilla_stealer" nocase ascii wide
                        $string43 = "function KematianLoader" nocase ascii wide
                        $string44 = "Get-InstalledAV " nocase ascii wide
                        $string45 = /https\:\/\/mainstream\.ngrok\.app\/\?method\=UploadFile\&filename\=/ nocase ascii wide
                        $string46 = /https\:\/\/ratte\.ngrok\.app\/main\/mainer/ nocase ascii wide
                        $string47 = /https\:\/\/t\.me\/encrypthub/ nocase ascii wide
                        $string48 = /https\:\/\/www\.win\-rar\.co\/panel\// nocase ascii wide
                        $string49 = /Invoke\-WebRequest\s\-Uri\s\\"http\:\/\/ip\-api\.com\/line\/\?/ nocase ascii wide
                        $string50 = "JGtlbWF0aWFuLlNldFZhbHVlKCRudWxsLCR0cnVlKQ==" nocase ascii wide
                        $string51 = "KioqUkFOU09NIE5PVEUqKgoKWW91ciBmaWxlcyBoYXZlIGJlZW4gZW5jcnlwdGVkLgoKQWxsIHlvdXIgaW1wb3J0YW50IGZpbGVzLCBpbmNsdWRpbm" nocase ascii wide
                        $string52 = /livevnc\.ngrok\.app/ nocase ascii wide
                        $string53 = /mshta\.exe\svbscript\:createobject\(\`\\"wscript\.shell\`\\"\)\.run\(\`\\"powershell\s/ nocase ascii wide
                        $string54 = "New-NetFirewallRule -DisplayName \"KematianC2\" " nocase ascii wide
                        $string55 = "openvpn_stealer" nocase ascii wide
                        $string56 = "Pirate-Devs/Kematian" nocase ascii wide
                        $string57 = "protonvpnstealer" nocase ascii wide
                        $string58 = /Remove\-Item\s\(Get\-PSreadlineOption\)\.HistorySavePath\s\-Force\s\-ErrorAction\sSilentlyContinue/ nocase ascii wide
                        $string59 = "sap3r-encrypthub/encrypthub" nocase ascii wide
                        $string60 = "Send-TelegramMessage -message " nocase ascii wide
                        $string61 = /\'Sil\'\+\'ent\'\+\'l\'\+\'yContinu\'\+\'e\'/ nocase ascii wide
                        $string62 = "surfsharkvpnstealer" nocase ascii wide
                        $string63 = "UmVkIFRlYW1pbmcgYW5kIE9mZmVuc2l2ZSBTZWN1cml0eSAg" nocase ascii wide
                        $string64 = "UmVtb3ZlLUl0ZW0gKEdldC1QU3JlYWRsaW5lT3B0aW9uKS5IaXN0b3J5U2F2ZVBhdGggLUZvcmNlIC1FcnJvckFjdGlvbiBTaWxlbnRseUNvbnRpbnVl" nocase ascii wide

    condition:
        any of them
}