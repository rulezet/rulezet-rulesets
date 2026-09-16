rule ToRat
{
    meta:
        description = "Detection patterns for the tool 'ToRat' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ToRat"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/dist:/dist_ext torat"
                        $string2 = /\/persist_cortana\.py/ nocase ascii wide
                        $string3 = /\/persist_people\.py/ nocase ascii wide
                        $string4 = /\/persit_linux\.go/
                        $string5 = /\/persit_windows\.go/ nocase ascii wide
                        $string6 = /\/ToRat\.git/ nocase ascii wide
                        $string7 = /\/tor\-static\-windows\-amd64\.zip/ nocase ascii wide
                        $string8 = /\\persist_cortana\.py/ nocase ascii wide
                        $string9 = /\\persist_people\.py/ nocase ascii wide
                        $string10 = /\\persit_linux\.go/ nocase ascii wide
                        $string11 = /\\persit_windows\.go/ nocase ascii wide
                        $string12 = /\\ToRat\\cmd\\/ nocase ascii wide
                        $string13 = /\\ToRat\\keygen\\/ nocase ascii wide
                        $string14 = /\\ToRat\\torat_client\\/ nocase ascii wide
                        $string15 = /\\ToRat\\torat_server\\/ nocase ascii wide
                        $string16 = /\\ToRat\-master\.zip/ nocase ascii wide
                        $string17 = /\\tor\-static\-windows\-amd64\.zip/ nocase ascii wide
                        $string18 = /docker\sbuild\s\.\s\-t\storat/ nocase ascii wide
                        $string19 = "docker run -it torat" nocase ascii wide
                        $string20 = /localhost\:8000\/.{0,100}\/hardware/ nocase ascii wide
                        $string21 = /localhost\:8000\/.{0,100}\/netscan/ nocase ascii wide
                        $string22 = /localhost\:8000\/.{0,100}\/osinfo/ nocase ascii wide
                        $string23 = /localhost\:8000\/.{0,100}\/speedtest/ nocase ascii wide
                        $string24 = "lu4p/ToRat" nocase ascii wide
                        $string25 = "server/ToRat_server" nocase ascii wide
                        $string26 = "torEd25519" nocase ascii wide
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