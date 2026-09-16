rule ghauri
{
    meta:
        description = "Detection patterns for the tool 'ghauri' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ghauri"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sGhauri\sis\sgoing\sto\suse\sthe\scurrent\sdatabase\sto\senumerate\stable\(s\)\sentries/ nocase ascii wide
                        $string2 = /\.py\s.{0,1000}\s\-\-sql\-shell/ nocase ascii wide
                        $string3 = /\/dbms\/fingerprint\.py/
                        $string4 = /\/ghauri\.git/ nocase ascii wide
                        $string5 = /\/ghauri\.py/ nocase ascii wide
                        $string6 = "/ghauri/ghauri/"
                        $string7 = /\\dbms\\fingerprint\.py/ nocase ascii wide
                        $string8 = /\\ghauri\\ghauri\\/ nocase ascii wide
                        $string9 = /\\ghauri\-1.{0,1000}\\ghauri\\/ nocase ascii wide
                        $string10 = "A cross-platform python based advanced sql injections detection & exploitation tool" nocase ascii wide
                        $string11 = /calling\sMySQL\sshell\.\sTo\squit\stype\s\'x\'\sor\s\'q\'\sand\spress\sENTER/ nocase ascii wide
                        $string12 = /Do\syou\swant\sGhauri\sset\sit\sfor\syou\s\?\s\[Y\/n\]/ nocase ascii wide
                        $string13 = /Do\syou\swant\sto\sskip\stest\spayloads\sspecific\sfor\sother\sDBMSes\?/ nocase ascii wide
                        $string14 = "ghauri currently only supports DBMS fingerprint payloads for Microsoft Access" nocase ascii wide
                        $string15 = "Ghauri detected connection errors multiple times" nocase ascii wide
                        $string16 = /Ghauri\sis\sexpecting\sdatabase\sname\sto\senumerate\stable\(s\)\sentries/ nocase ascii wide
                        $string17 = "ghauri -u " nocase ascii wide
                        $string18 = /ghauri\-.{0,1000}\\ghauri\-/ nocase ascii wide
                        $string19 = /ghauri\.common\.config/ nocase ascii wide
                        $string20 = /ghauri\.common\.lib/ nocase ascii wide
                        $string21 = /ghauri\.common\.payloads/ nocase ascii wide
                        $string22 = /ghauri\.common\.session/ nocase ascii wide
                        $string23 = /ghauri\.common\.utils/ nocase ascii wide
                        $string24 = /ghauri\.core\.extract/ nocase ascii wide
                        $string25 = /ghauri\.core\.tests/ nocase ascii wide
                        $string26 = /ghauri\.extractor\.advance/ nocase ascii wide
                        $string27 = /ghauri\.py\s/ nocase ascii wide
                        $string28 = "ghauri_extractor" nocase ascii wide
                        $string29 = /ghauri\-main\.zip/ nocase ascii wide
                        $string30 = /http\:\/\/www\.site\.com\/article\.php\?id\=1/ nocase ascii wide
                        $string31 = /http\:\/\/www\.site\.com\/vuln\.php\?id\=1\s\-\-dbs/ nocase ascii wide
                        $string32 = /Nasir\sKhan\s\(r0ot\sh3x49\)/ nocase ascii wide
                        $string33 = "r0oth3x49/ghauri" nocase ascii wide
                        $string34 = /r0oth3x49\@gmail\.com/ nocase ascii wide
                        $string35 = /scripts\/ghauri\.py/ nocase ascii wide
                        $string36 = /scripts\\ghauri\.py/ nocase ascii wide
                        $string37 = "sqlmapproject/sqlmap/issues/2442" nocase ascii wide
                        $string38 = /testing\sfor\sSQL\sinjection\son\s\(custom\)/ nocase ascii wide
                        $string39 = /user\saborted\sduring\sDBMS\sfingerprint\./ nocase ascii wide

    condition:
        any of them
}