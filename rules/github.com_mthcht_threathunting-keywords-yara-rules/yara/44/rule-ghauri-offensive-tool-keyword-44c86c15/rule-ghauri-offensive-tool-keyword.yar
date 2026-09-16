rule rule_ghauri_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ghauri' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ghauri"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ghauri_offensive_tool_keyword = /\sGhauri\sis\sgoing\sto\suse\sthe\scurrent\sdatabase\sto\senumerate\stable\(s\)\sentries/ nocase ascii wide
                        $string2_ghauri_offensive_tool_keyword = /\.py\s.{0,1000}\s\-\-sql\-shell/ nocase ascii wide
                        $string3_ghauri_offensive_tool_keyword = /\/dbms\/fingerprint\.py/
                        $string4_ghauri_offensive_tool_keyword = /\/ghauri\.git/ nocase ascii wide
                        $string5_ghauri_offensive_tool_keyword = /\/ghauri\.py/ nocase ascii wide
                        $string6_ghauri_offensive_tool_keyword = "/ghauri/ghauri/"
                        $string7_ghauri_offensive_tool_keyword = /\\dbms\\fingerprint\.py/ nocase ascii wide
                        $string8_ghauri_offensive_tool_keyword = /\\ghauri\\ghauri\\/ nocase ascii wide
                        $string9_ghauri_offensive_tool_keyword = /\\ghauri\-1.{0,1000}\\ghauri\\/ nocase ascii wide
                        $string10_ghauri_offensive_tool_keyword = "A cross-platform python based advanced sql injections detection & exploitation tool" nocase ascii wide
                        $string11_ghauri_offensive_tool_keyword = /calling\sMySQL\sshell\.\sTo\squit\stype\s\'x\'\sor\s\'q\'\sand\spress\sENTER/ nocase ascii wide
                        $string12_ghauri_offensive_tool_keyword = /Do\syou\swant\sGhauri\sset\sit\sfor\syou\s\?\s\[Y\/n\]/ nocase ascii wide
                        $string13_ghauri_offensive_tool_keyword = /Do\syou\swant\sto\sskip\stest\spayloads\sspecific\sfor\sother\sDBMSes\?/ nocase ascii wide
                        $string14_ghauri_offensive_tool_keyword = "ghauri currently only supports DBMS fingerprint payloads for Microsoft Access" nocase ascii wide
                        $string15_ghauri_offensive_tool_keyword = "Ghauri detected connection errors multiple times" nocase ascii wide
                        $string16_ghauri_offensive_tool_keyword = /Ghauri\sis\sexpecting\sdatabase\sname\sto\senumerate\stable\(s\)\sentries/ nocase ascii wide
                        $string17_ghauri_offensive_tool_keyword = "ghauri -u " nocase ascii wide
                        $string18_ghauri_offensive_tool_keyword = /ghauri\-.{0,1000}\\ghauri\-/ nocase ascii wide
                        $string19_ghauri_offensive_tool_keyword = /ghauri\.common\.config/ nocase ascii wide
                        $string20_ghauri_offensive_tool_keyword = /ghauri\.common\.lib/ nocase ascii wide
                        $string21_ghauri_offensive_tool_keyword = /ghauri\.common\.payloads/ nocase ascii wide
                        $string22_ghauri_offensive_tool_keyword = /ghauri\.common\.session/ nocase ascii wide
                        $string23_ghauri_offensive_tool_keyword = /ghauri\.common\.utils/ nocase ascii wide
                        $string24_ghauri_offensive_tool_keyword = /ghauri\.core\.extract/ nocase ascii wide
                        $string25_ghauri_offensive_tool_keyword = /ghauri\.core\.tests/ nocase ascii wide
                        $string26_ghauri_offensive_tool_keyword = /ghauri\.extractor\.advance/ nocase ascii wide
                        $string27_ghauri_offensive_tool_keyword = /ghauri\.py\s/ nocase ascii wide
                        $string28_ghauri_offensive_tool_keyword = "ghauri_extractor" nocase ascii wide
                        $string29_ghauri_offensive_tool_keyword = /ghauri\-main\.zip/ nocase ascii wide
                        $string30_ghauri_offensive_tool_keyword = /http\:\/\/www\.site\.com\/article\.php\?id\=1/ nocase ascii wide
                        $string31_ghauri_offensive_tool_keyword = /http\:\/\/www\.site\.com\/vuln\.php\?id\=1\s\-\-dbs/ nocase ascii wide
                        $string32_ghauri_offensive_tool_keyword = /Nasir\sKhan\s\(r0ot\sh3x49\)/ nocase ascii wide
                        $string33_ghauri_offensive_tool_keyword = "r0oth3x49/ghauri" nocase ascii wide
                        $string34_ghauri_offensive_tool_keyword = /r0oth3x49\@gmail\.com/ nocase ascii wide
                        $string35_ghauri_offensive_tool_keyword = /scripts\/ghauri\.py/ nocase ascii wide
                        $string36_ghauri_offensive_tool_keyword = /scripts\\ghauri\.py/ nocase ascii wide
                        $string37_ghauri_offensive_tool_keyword = "sqlmapproject/sqlmap/issues/2442" nocase ascii wide
                        $string38_ghauri_offensive_tool_keyword = /testing\sfor\sSQL\sinjection\son\s\(custom\)/ nocase ascii wide
                        $string39_ghauri_offensive_tool_keyword = /user\saborted\sduring\sDBMS\sfingerprint\./ nocase ascii wide

    condition:
        any of them
}