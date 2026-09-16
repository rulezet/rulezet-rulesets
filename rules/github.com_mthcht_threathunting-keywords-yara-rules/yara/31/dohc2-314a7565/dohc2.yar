rule DoHC2
{
    meta:
        description = "Detection patterns for the tool 'DoHC2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DoHC2"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/BeaconChannel\.cs/ nocase ascii wide
                        $string2 = /\/DoHC2\.cs/ nocase ascii wide
                        $string3 = /\/DoHC2\.git/ nocase ascii wide
                        $string4 = "/DoHC2/" nocase ascii wide
                        $string5 = "/ExternalC2/" nocase ascii wide
                        $string6 = /\/WebC2\.cs/
                        $string7 = /\/WebSocketC2\.cs/ nocase ascii wide
                        $string8 = /\\BeaconChannel\.cs/ nocase ascii wide
                        $string9 = /\\BeaconConnector\.cs/ nocase ascii wide
                        $string10 = /\\DoHC2\.cs/ nocase ascii wide
                        $string11 = /\\ExternalC2\\/ nocase ascii wide
                        $string12 = /0\.0\.0\.0\:2222/ nocase ascii wide
                        $string13 = /127\.0\.0\.1\:2222/ nocase ascii wide
                        $string14 = /C2WebSocketHandler\./ nocase ascii wide
                        $string15 = "Cobalt Strike external C2" nocase ascii wide
                        $string16 = /DoHC2.{0,100}BeaconConnector/ nocase ascii wide
                        $string17 = /DoHC2\.exe/ nocase ascii wide
                        $string18 = /DoHC2\.py/ nocase ascii wide
                        $string19 = /DoHC2Runner\./ nocase ascii wide
                        $string20 = /DoHC2Runner\.exe/ nocase ascii wide
                        $string21 = /DoHC2Runner\.pdb/ nocase ascii wide
                        $string22 = /DoHChannel\.cs/ nocase ascii wide
                        $string23 = /external_c2\.cna/ nocase ascii wide
                        $string24 = /ExternalC2\./ nocase ascii wide
                        $string25 = /ExternalC2\.dll/ nocase ascii wide
                        $string26 = "externalc2_start" nocase ascii wide
                        $string27 = "ExternalC2Core" nocase ascii wide
                        $string28 = "ExternalC2-master" nocase ascii wide
                        $string29 = "ExternalC2Tests" nocase ascii wide
                        $string30 = "ExternalC2Web" nocase ascii wide
                        $string31 = "go-external-c2" nocase ascii wide
                        $string32 = "package externc2" nocase ascii wide
                        $string33 = "SpiderLabs/DoHC2" nocase ascii wide
                        $string34 = "X-C2-Beacon" nocase ascii wide
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