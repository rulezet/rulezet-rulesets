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
                        $string2 = /\.py\s.{0,100}\s\-\-sql\-shell/ nocase ascii wide
                        $string3 = /\/dbms\/fingerprint\.py/
                        $string4 = /\/ghauri\.git/ nocase ascii wide
                        $string5 = /\/ghauri\.py/ nocase ascii wide
                        $string6 = "/ghauri/ghauri/"
                        $string7 = /\\dbms\\fingerprint\.py/ nocase ascii wide
                        $string8 = /\\ghauri\\ghauri\\/ nocase ascii wide
                        $string9 = /\\ghauri\-1.{0,100}\\ghauri\\/ nocase ascii wide
                        $string10 = "A cross-platform python based advanced sql injections detection & exploitation tool" nocase ascii wide
                        $string11 = /calling\sMySQL\sshell\.\sTo\squit\stype\s\'x\'\sor\s\'q\'\sand\spress\sENTER/ nocase ascii wide
                        $string12 = /Do\syou\swant\sGhauri\sset\sit\sfor\syou\s\?\s\[Y\/n\]/ nocase ascii wide
                        $string13 = /Do\syou\swant\sto\sskip\stest\spayloads\sspecific\sfor\sother\sDBMSes\?/ nocase ascii wide
                        $string14 = "ghauri currently only supports DBMS fingerprint payloads for Microsoft Access" nocase ascii wide
                        $string15 = "Ghauri detected connection errors multiple times" nocase ascii wide
                        $string16 = /Ghauri\sis\sexpecting\sdatabase\sname\sto\senumerate\stable\(s\)\sentries/ nocase ascii wide
                        $string17 = "ghauri -u " nocase ascii wide
                        $string18 = /ghauri\-.{0,100}\\ghauri\-/ nocase ascii wide
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