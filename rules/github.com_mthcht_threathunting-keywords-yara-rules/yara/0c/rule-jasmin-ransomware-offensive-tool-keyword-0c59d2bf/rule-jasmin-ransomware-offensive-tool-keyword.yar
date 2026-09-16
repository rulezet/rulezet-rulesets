rule rule_Jasmin_Ransomware_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Jasmin-Ransomware' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Jasmin-Ransomware"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Jasmin_Ransomware_offensive_tool_keyword = /\s\-u\sjasminadmin\s\-p.{0,1000}\sjasmin_db\s/ nocase ascii wide
                        $string2_Jasmin_Ransomware_offensive_tool_keyword = /\.500\.jasmin/ nocase ascii wide
                        $string3_Jasmin_Ransomware_offensive_tool_keyword = /\.docx\.jasmin/ nocase ascii wide
                        $string4_Jasmin_Ransomware_offensive_tool_keyword = /\.jpeg\.jasmin/ nocase ascii wide
                        $string5_Jasmin_Ransomware_offensive_tool_keyword = /\.jpg\.jasmin/ nocase ascii wide
                        $string6_Jasmin_Ransomware_offensive_tool_keyword = /\.pdf\.jasmin/ nocase ascii wide
                        $string7_Jasmin_Ransomware_offensive_tool_keyword = /\.png\.jasmin/ nocase ascii wide
                        $string8_Jasmin_Ransomware_offensive_tool_keyword = /\.pptx\.jasmin/ nocase ascii wide
                        $string9_Jasmin_Ransomware_offensive_tool_keyword = /\.txt\.jasmin/ nocase ascii wide
                        $string10_Jasmin_Ransomware_offensive_tool_keyword = /\.xlsx\.jasmin/ nocase ascii wide
                        $string11_Jasmin_Ransomware_offensive_tool_keyword = /\/jasmin\-ransomware\.git/ nocase ascii wide
                        $string12_Jasmin_Ransomware_offensive_tool_keyword = /\\Jasmin\sDecryptor\\/ nocase ascii wide
                        $string13_Jasmin_Ransomware_offensive_tool_keyword = /\\Jasmin\sDecryptor\\/ nocase ascii wide
                        $string14_Jasmin_Ransomware_offensive_tool_keyword = /\\Jasmin\sRansomware\sFinal\\/ nocase ascii wide
                        $string15_Jasmin_Ransomware_offensive_tool_keyword = /\\unlock\syour\sfiles\.lnk/ nocase ascii wide
                        $string16_Jasmin_Ransomware_offensive_tool_keyword = /\\Users\\Public\\Windows\\Ui/ nocase ascii wide
                        $string17_Jasmin_Ransomware_offensive_tool_keyword = /\\Users\\Public\\Windows\\Ui\\/ nocase ascii wide
                        $string18_Jasmin_Ransomware_offensive_tool_keyword = /\\Windows\\Ui\\index\.html/ nocase ascii wide
                        $string19_Jasmin_Ransomware_offensive_tool_keyword = ">-Infected Systems Database-</span>" nocase ascii wide
                        $string20_Jasmin_Ransomware_offensive_tool_keyword = ">Jasmin Encryptor<" nocase ascii wide
                        $string21_Jasmin_Ransomware_offensive_tool_keyword = ">Jasmin Ransomware</div>" nocase ascii wide
                        $string22_Jasmin_Ransomware_offensive_tool_keyword = "6FF9974C-B3C6-4EEA-8472-22BE6BD6F5CD" nocase ascii wide
                        $string23_Jasmin_Ransomware_offensive_tool_keyword = "78C76961-8249-4EFE-9DE2-B6EF15A187F7" nocase ascii wide
                        $string24_Jasmin_Ransomware_offensive_tool_keyword = "ba41cc2f4c5dfb7df874b0e92f99f33b37b11574aab288d229749eba00e98813" nocase ascii wide
                        $string25_Jasmin_Ransomware_offensive_tool_keyword = /C\:\\\\Users\\\\Public\\\\Windows\\\\Ui\\\\/ nocase ascii wide
                        $string26_Jasmin_Ransomware_offensive_tool_keyword = /C\:\\Users\\cyberstair\\/ nocase ascii wide
                        $string27_Jasmin_Ransomware_offensive_tool_keyword = "c062b58a1151df4a0ebad3d9246f69342b0ac1ecf5e5a5c4116f292994c481bd" nocase ascii wide
                        $string28_Jasmin_Ransomware_offensive_tool_keyword = "c51005736c67304bf96c0e5421ce44f700578b87dbc912a820fd38dfa146fe41" nocase ascii wide
                        $string29_Jasmin_Ransomware_offensive_tool_keyword = "codesiddhant/jasmin-ransomware" nocase ascii wide
                        $string30_Jasmin_Ransomware_offensive_tool_keyword = /ConsoleHost_history\.txt\.jasmin/ nocase ascii wide
                        $string31_Jasmin_Ransomware_offensive_tool_keyword = "CREATE DATABASE jasmin_db" nocase ascii wide
                        $string32_Jasmin_Ransomware_offensive_tool_keyword = "d24cfba28aeecfecb7698350ca04c4ed07f6a9b88b212bbcbaacd168372fa980" nocase ascii wide
                        $string33_Jasmin_Ransomware_offensive_tool_keyword = /GRANT\sALL\sPRIVILEGES\sON\sjasmin_db\./ nocase ascii wide
                        $string34_Jasmin_Ransomware_offensive_tool_keyword = /handshake.{0,1000}jasmin\@123/ nocase ascii wide
                        $string35_Jasmin_Ransomware_offensive_tool_keyword = /htdocs\/database\/jasmin_db\.sql/ nocase ascii wide
                        $string36_Jasmin_Ransomware_offensive_tool_keyword = /http.{0,1000}\/alertmsg\.zip/ nocase ascii wide
                        $string37_Jasmin_Ransomware_offensive_tool_keyword = /http\:\/\/127\.0\.0\.1\/handshake\.php/ nocase ascii wide
                        $string38_Jasmin_Ransomware_offensive_tool_keyword = /https\:\/\/cnc\.mkbot\.info\/alertmsg\.zip/ nocase ascii wide
                        $string39_Jasmin_Ransomware_offensive_tool_keyword = /https\:\/\/cnc\.mkbot\.info\/handshake\.php/ nocase ascii wide
                        $string40_Jasmin_Ransomware_offensive_tool_keyword = /Jasmin\sDecryptor\.csproj/ nocase ascii wide
                        $string41_Jasmin_Ransomware_offensive_tool_keyword = /Jasmin\sDecryptor\.exe/ nocase ascii wide
                        $string42_Jasmin_Ransomware_offensive_tool_keyword = /Jasmin\sDecryptor\.pdb/ nocase ascii wide
                        $string43_Jasmin_Ransomware_offensive_tool_keyword = /Jasmin\sDecryptor\.sln/ nocase ascii wide
                        $string44_Jasmin_Ransomware_offensive_tool_keyword = /Jasmin\sEncryptor\.csproj/ nocase ascii wide
                        $string45_Jasmin_Ransomware_offensive_tool_keyword = /Jasmin\sEncryptor\.exe/ nocase ascii wide
                        $string46_Jasmin_Ransomware_offensive_tool_keyword = /Jasmin\sEncryptor\.sln/ nocase ascii wide
                        $string47_Jasmin_Ransomware_offensive_tool_keyword = /Jasmin\sEncryptor\\bin\\Release/ nocase ascii wide
                        $string48_Jasmin_Ransomware_offensive_tool_keyword = "Jasmin Ransomware C2 Checkin" nocase ascii wide
                        $string49_Jasmin_Ransomware_offensive_tool_keyword = /Jasmin\%20Decryptor\.exe/ nocase ascii wide
                        $string50_Jasmin_Ransomware_offensive_tool_keyword = /Jasmin\%20Decryptor\.pdb/ nocase ascii wide
                        $string51_Jasmin_Ransomware_offensive_tool_keyword = /Jasmin\%20Encryptor\.exe/ nocase ascii wide
                        $string52_Jasmin_Ransomware_offensive_tool_keyword = /Jasmin_Decryptor\.mainform/ nocase ascii wide
                        $string53_Jasmin_Ransomware_offensive_tool_keyword = /Jasmin_Decryptor\.Properties/ nocase ascii wide
                        $string54_Jasmin_Ransomware_offensive_tool_keyword = "'jasminadmin'@'localhost'" nocase ascii wide
                        $string55_Jasmin_Ransomware_offensive_tool_keyword = "jasmin-ransomware-master" nocase ascii wide
                        $string56_Jasmin_Ransomware_offensive_tool_keyword = "namespace Jasmin_Encrypter" nocase ascii wide
                        $string57_Jasmin_Ransomware_offensive_tool_keyword = "The Ransomware for RedTeams Coded by Siddhant Gour with " nocase ascii wide
                        $string58_Jasmin_Ransomware_offensive_tool_keyword = "VXpCMk1UTjBjMU14YkhZemNsSTBibk13YlhjMGNqTQ" nocase ascii wide

    condition:
        any of them
}