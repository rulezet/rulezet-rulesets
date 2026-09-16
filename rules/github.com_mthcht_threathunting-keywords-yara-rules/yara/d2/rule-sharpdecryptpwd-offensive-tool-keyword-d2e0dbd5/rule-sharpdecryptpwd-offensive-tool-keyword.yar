rule rule_SharpDecryptPwd_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpDecryptPwd' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpDecryptPwd"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SharpDecryptPwd_offensive_tool_keyword = /\.exe\sXmanager\s\/user\:.{0,1000}\s\/sid\:.{0,1000}\s\/path\:/ nocase ascii wide
                        $string2_SharpDecryptPwd_offensive_tool_keyword = /\.exe\s\-Xmangager\s\-p\s/ nocase ascii wide
                        $string3_SharpDecryptPwd_offensive_tool_keyword = /\/SharpDecryptPwd\.git/ nocase ascii wide
                        $string4_SharpDecryptPwd_offensive_tool_keyword = /\\FoxmailDump\.cpp/ nocase ascii wide
                        $string5_SharpDecryptPwd_offensive_tool_keyword = /\\SharpDecryptPwd\.sln/ nocase ascii wide
                        $string6_SharpDecryptPwd_offensive_tool_keyword = /\\SharpDecryptPwd\\/ nocase ascii wide
                        $string7_SharpDecryptPwd_offensive_tool_keyword = /\\SharpDecryptPwd\-main/ nocase ascii wide
                        $string8_SharpDecryptPwd_offensive_tool_keyword = ">SharpDecryptPwd<" nocase ascii wide
                        $string9_SharpDecryptPwd_offensive_tool_keyword = "1824ED63-BE4D-4306-919D-9C749C1AE271" nocase ascii wide
                        $string10_SharpDecryptPwd_offensive_tool_keyword = "1f385acf11f8ea6673d7295be6492ea9913b525da25dcc037ea49ef4f86a9d58" nocase ascii wide
                        $string11_SharpDecryptPwd_offensive_tool_keyword = "2273f47d253c1974f82b9b7f9018228080e8ac41b75bba4e779fe9f918d72aa1" nocase ascii wide
                        $string12_SharpDecryptPwd_offensive_tool_keyword = "537dfda00b6ce57ca35f3da4eaac5cfc42c4180d5573673a66c4665517d0a208" nocase ascii wide
                        $string13_SharpDecryptPwd_offensive_tool_keyword = "80ed17895205205c5a769d18715cb74a623cee6a5379bb8142d2c8c533c759b2" nocase ascii wide
                        $string14_SharpDecryptPwd_offensive_tool_keyword = "RowTeam/SharpDecryptPwd" nocase ascii wide
                        $string15_SharpDecryptPwd_offensive_tool_keyword = "SharpDecryptPwd " nocase ascii wide
                        $string16_SharpDecryptPwd_offensive_tool_keyword = /SharpDecryptPwd\.Commands/ nocase ascii wide
                        $string17_SharpDecryptPwd_offensive_tool_keyword = /SharpDecryptPwd\.csproj/ nocase ascii wide
                        $string18_SharpDecryptPwd_offensive_tool_keyword = /SharpDecryptPwd\.exe/ nocase ascii wide
                        $string19_SharpDecryptPwd_offensive_tool_keyword = /SharpDecryptPwd\.exe/ nocase ascii wide
                        $string20_SharpDecryptPwd_offensive_tool_keyword = /SharpDecryptPwd\.Lib/ nocase ascii wide
                        $string21_SharpDecryptPwd_offensive_tool_keyword = /SharpDecryptPwd\.Properties/ nocase ascii wide
                        $string22_SharpDecryptPwd_offensive_tool_keyword = "uknowsec/SharpDecryptPwd" nocase ascii wide
                        $string23_SharpDecryptPwd_offensive_tool_keyword = "using SharpDecryptPwd" nocase ascii wide

    condition:
        any of them
}