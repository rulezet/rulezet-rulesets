rule rule_wso_webshell_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'wso-webshell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wso-webshell"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_wso_webshell_offensive_tool_keyword = /\/wso\-webshell\.git/ nocase ascii wide
                        $string2_wso_webshell_offensive_tool_keyword = "1e7a48d3a266ff3a1521da0804858af56093f9c736c06be2bc6b46502a776d5d" nocase ascii wide
                        $string3_wso_webshell_offensive_tool_keyword = "DQojaW5jbHVkZSA8c3lzL3NvY2tldC5oPg0KI2luY2x1ZGUgPG5ldGluZXQvaW4uaD4NCmludCBtYWluKGludCBhcmdjLCBjaGFyICphcmd" nocase ascii wide
                        $string4_wso_webshell_offensive_tool_keyword = "fa769dac7a0a94ee47d8ebe021eaba9e" nocase ascii wide
                        $string5_wso_webshell_offensive_tool_keyword = /find\s\.\s\-perm\s\-2\s\-ls/
                        $string6_wso_webshell_offensive_tool_keyword = /find\s\.\s\-type\sf\s\-name\s\.bash_history/
                        $string7_wso_webshell_offensive_tool_keyword = /find\s\.\s\-type\sf\s\-name\s\.fetchmailrc/
                        $string8_wso_webshell_offensive_tool_keyword = /find\s\.\s\-type\sf\s\-name\s\.htpasswd/
                        $string9_wso_webshell_offensive_tool_keyword = /find\s\.\s\-type\sf\s\-name\sservice\.pwd/
                        $string10_wso_webshell_offensive_tool_keyword = /find\s\.\s\-type\sf\s\-perm\s\-02000\s\-ls/
                        $string11_wso_webshell_offensive_tool_keyword = /find\s\.\s\-type\sf\s\-perm\s\-04000\s\-ls/
                        $string12_wso_webshell_offensive_tool_keyword = "find / -perm -2 -ls"
                        $string13_wso_webshell_offensive_tool_keyword = /find\s\/\s\-type\sf\s\-name\s\.bash_history/
                        $string14_wso_webshell_offensive_tool_keyword = /find\s\/\s\-type\sf\s\-name\s\.fetchmailrc/
                        $string15_wso_webshell_offensive_tool_keyword = /find\s\/\s\-type\sf\s\-name\s\.htpasswd/
                        $string16_wso_webshell_offensive_tool_keyword = /find\s\/\s\-type\sf\s\-name\sconfig\.inc\.php/
                        $string17_wso_webshell_offensive_tool_keyword = /find\s\/\s\-type\sf\s\-name\sservice\.pwd/
                        $string18_wso_webshell_offensive_tool_keyword = "find / -type f -perm -02000 -ls"
                        $string19_wso_webshell_offensive_tool_keyword = "find / -type f -perm -04000 -ls"
                        $string20_wso_webshell_offensive_tool_keyword = /function\sactionBruteforce\(\)\s\{/ nocase ascii wide
                        $string21_wso_webshell_offensive_tool_keyword = /I2luY2x1ZGUgPHN0ZGlvLmg\+DQojaW5jbHVkZSA8c3RyaW5nLmg\+DQojaW5jbHVkZSA8dW5pc3RkLmg\+DQojaW5jbHVkZSA8bmV0ZGIuaD4NCiNpbmNsdWRlIDxzdGRsaWI/ nocase ascii wide
                        $string22_wso_webshell_offensive_tool_keyword = "IyEvdXNyL2Jpbi9wZXJsDQokU0hFTEw9Ii9iaW4vc2ggLWkiOw0KaWYgKEBBUkdWIDwgMSkgeyBleGl0KDEpOyB9DQp1c2UgU29ja2V0Ow0Kc29ja2V0KFMsJlBGX0lO" nocase ascii wide
                        $string23_wso_webshell_offensive_tool_keyword = "IyEvdXNyL2Jpbi9wZXJsDQp1c2UgU29ja2V0Ow0KJGlhZGRyPWluZXRfYXRvbigkQVJHVlswXSkgfHwgZGllKCJFcnJvcjogJCFcbiIpOw0KJHBhZGRyPXNvY2thZGRyX" nocase ascii wide
                        $string24_wso_webshell_offensive_tool_keyword = "mIcHyAmRaNe/wso-webshell" nocase ascii wide
                        $string25_wso_webshell_offensive_tool_keyword = "Welcome to wso webshell " nocase ascii wide

    condition:
        any of them
}