rule SharpDecryptPwd
{
    meta:
        description = "Detection patterns for the tool 'SharpDecryptPwd' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpDecryptPwd"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\.exe\sXmanager\s\/user\:.{0,1000}\s\/sid\:.{0,1000}\s\/path\:/ nocase ascii wide
                        $string2 = /\.exe\s\-Xmangager\s\-p\s/ nocase ascii wide
                        $string3 = /\/SharpDecryptPwd\.git/ nocase ascii wide
                        $string4 = /\\FoxmailDump\.cpp/ nocase ascii wide
                        $string5 = /\\SharpDecryptPwd\.sln/ nocase ascii wide
                        $string6 = /\\SharpDecryptPwd\\/ nocase ascii wide
                        $string7 = /\\SharpDecryptPwd\-main/ nocase ascii wide
                        $string8 = ">SharpDecryptPwd<" nocase ascii wide
                        $string9 = "1824ED63-BE4D-4306-919D-9C749C1AE271" nocase ascii wide
                        $string10 = "1f385acf11f8ea6673d7295be6492ea9913b525da25dcc037ea49ef4f86a9d58" nocase ascii wide
                        $string11 = "2273f47d253c1974f82b9b7f9018228080e8ac41b75bba4e779fe9f918d72aa1" nocase ascii wide
                        $string12 = "537dfda00b6ce57ca35f3da4eaac5cfc42c4180d5573673a66c4665517d0a208" nocase ascii wide
                        $string13 = "80ed17895205205c5a769d18715cb74a623cee6a5379bb8142d2c8c533c759b2" nocase ascii wide
                        $string14 = "RowTeam/SharpDecryptPwd" nocase ascii wide
                        $string15 = "SharpDecryptPwd " nocase ascii wide
                        $string16 = /SharpDecryptPwd\.Commands/ nocase ascii wide
                        $string17 = /SharpDecryptPwd\.csproj/ nocase ascii wide
                        $string18 = /SharpDecryptPwd\.exe/ nocase ascii wide
                        $string19 = /SharpDecryptPwd\.exe/ nocase ascii wide
                        $string20 = /SharpDecryptPwd\.Lib/ nocase ascii wide
                        $string21 = /SharpDecryptPwd\.Properties/ nocase ascii wide
                        $string22 = "uknowsec/SharpDecryptPwd" nocase ascii wide
                        $string23 = "using SharpDecryptPwd" nocase ascii wide

    condition:
        any of them
}