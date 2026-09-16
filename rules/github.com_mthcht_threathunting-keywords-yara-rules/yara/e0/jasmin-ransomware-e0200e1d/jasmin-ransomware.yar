rule Jasmin_Ransomware
{
    meta:
        description = "Detection patterns for the tool 'Jasmin-Ransomware' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Jasmin-Ransomware"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\-u\sjasminadmin\s\-p.{0,1000}\sjasmin_db\s/ nocase ascii wide
                        $string2 = /\.500\.jasmin/ nocase ascii wide
                        $string3 = /\.docx\.jasmin/ nocase ascii wide
                        $string4 = /\.jpeg\.jasmin/ nocase ascii wide
                        $string5 = /\.jpg\.jasmin/ nocase ascii wide
                        $string6 = /\.pdf\.jasmin/ nocase ascii wide
                        $string7 = /\.png\.jasmin/ nocase ascii wide
                        $string8 = /\.pptx\.jasmin/ nocase ascii wide
                        $string9 = /\.txt\.jasmin/ nocase ascii wide
                        $string10 = /\.xlsx\.jasmin/ nocase ascii wide
                        $string11 = /\/jasmin\-ransomware\.git/ nocase ascii wide
                        $string12 = /\\Jasmin\sDecryptor\\/ nocase ascii wide
                        $string13 = /\\Jasmin\sDecryptor\\/ nocase ascii wide
                        $string14 = /\\Jasmin\sRansomware\sFinal\\/ nocase ascii wide
                        $string15 = /\\unlock\syour\sfiles\.lnk/ nocase ascii wide
                        $string16 = /\\Users\\Public\\Windows\\Ui/ nocase ascii wide
                        $string17 = /\\Users\\Public\\Windows\\Ui\\/ nocase ascii wide
                        $string18 = /\\Windows\\Ui\\index\.html/ nocase ascii wide
                        $string19 = ">-Infected Systems Database-</span>" nocase ascii wide
                        $string20 = ">Jasmin Encryptor<" nocase ascii wide
                        $string21 = ">Jasmin Ransomware</div>" nocase ascii wide
                        $string22 = "6FF9974C-B3C6-4EEA-8472-22BE6BD6F5CD" nocase ascii wide
                        $string23 = "78C76961-8249-4EFE-9DE2-B6EF15A187F7" nocase ascii wide
                        $string24 = "ba41cc2f4c5dfb7df874b0e92f99f33b37b11574aab288d229749eba00e98813" nocase ascii wide
                        $string25 = /C\:\\\\Users\\\\Public\\\\Windows\\\\Ui\\\\/ nocase ascii wide
                        $string26 = /C\:\\Users\\cyberstair\\/ nocase ascii wide
                        $string27 = "c062b58a1151df4a0ebad3d9246f69342b0ac1ecf5e5a5c4116f292994c481bd" nocase ascii wide
                        $string28 = "c51005736c67304bf96c0e5421ce44f700578b87dbc912a820fd38dfa146fe41" nocase ascii wide
                        $string29 = "codesiddhant/jasmin-ransomware" nocase ascii wide
                        $string30 = /ConsoleHost_history\.txt\.jasmin/ nocase ascii wide
                        $string31 = "CREATE DATABASE jasmin_db" nocase ascii wide
                        $string32 = "d24cfba28aeecfecb7698350ca04c4ed07f6a9b88b212bbcbaacd168372fa980" nocase ascii wide
                        $string33 = /GRANT\sALL\sPRIVILEGES\sON\sjasmin_db\./ nocase ascii wide
                        $string34 = /handshake.{0,1000}jasmin\@123/ nocase ascii wide
                        $string35 = /htdocs\/database\/jasmin_db\.sql/ nocase ascii wide
                        $string36 = /http.{0,1000}\/alertmsg\.zip/ nocase ascii wide
                        $string37 = /http\:\/\/127\.0\.0\.1\/handshake\.php/ nocase ascii wide
                        $string38 = /https\:\/\/cnc\.mkbot\.info\/alertmsg\.zip/ nocase ascii wide
                        $string39 = /https\:\/\/cnc\.mkbot\.info\/handshake\.php/ nocase ascii wide
                        $string40 = /Jasmin\sDecryptor\.csproj/ nocase ascii wide
                        $string41 = /Jasmin\sDecryptor\.exe/ nocase ascii wide
                        $string42 = /Jasmin\sDecryptor\.pdb/ nocase ascii wide
                        $string43 = /Jasmin\sDecryptor\.sln/ nocase ascii wide
                        $string44 = /Jasmin\sEncryptor\.csproj/ nocase ascii wide
                        $string45 = /Jasmin\sEncryptor\.exe/ nocase ascii wide
                        $string46 = /Jasmin\sEncryptor\.sln/ nocase ascii wide
                        $string47 = /Jasmin\sEncryptor\\bin\\Release/ nocase ascii wide
                        $string48 = "Jasmin Ransomware C2 Checkin" nocase ascii wide
                        $string49 = /Jasmin\%20Decryptor\.exe/ nocase ascii wide
                        $string50 = /Jasmin\%20Decryptor\.pdb/ nocase ascii wide
                        $string51 = /Jasmin\%20Encryptor\.exe/ nocase ascii wide
                        $string52 = /Jasmin_Decryptor\.mainform/ nocase ascii wide
                        $string53 = /Jasmin_Decryptor\.Properties/ nocase ascii wide
                        $string54 = "'jasminadmin'@'localhost'" nocase ascii wide
                        $string55 = "jasmin-ransomware-master" nocase ascii wide
                        $string56 = "namespace Jasmin_Encrypter" nocase ascii wide
                        $string57 = "The Ransomware for RedTeams Coded by Siddhant Gour with " nocase ascii wide
                        $string58 = "VXpCMk1UTjBjMU14YkhZemNsSTBibk13YlhjMGNqTQ" nocase ascii wide

    condition:
        any of them
}