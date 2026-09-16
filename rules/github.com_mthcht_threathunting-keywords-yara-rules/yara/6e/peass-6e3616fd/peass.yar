rule PEASS
{
    meta:
        description = "Detection patterns for the tool 'PEASS' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PEASS"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " import LinpeasBaseBuilder" nocase ascii wide
                        $string2 = " import LinpeasBuilder" nocase ascii wide
                        $string3 = " import PEASLoaded" nocase ascii wide
                        $string4 = " import PEASRecord" nocase ascii wide
                        $string5 = /\slinpeas\.sh\s/
                        $string6 = " -linpeas=http://" nocase ascii wide
                        $string7 = /\s\-linpeas\=http\:\/\/127\.0\.0\.1\/linpeas\.sh/ nocase ascii wide
                        $string8 = " WinPEAS - Windows local Privilege Escalation Awesome Script" nocase ascii wide
                        $string9 = /\.exe\s\s\-lolbas\slog/ nocase ascii wide
                        $string10 = /\/linpeas\.sh/ nocase ascii wide
                        $string11 = /\/linpeas\.sh/ nocase ascii wide
                        $string12 = /\/linpeas\.txt/ nocase ascii wide
                        $string13 = /\/linpeasBaseBuilder\.py/ nocase ascii wide
                        $string14 = /\/linpeasBuilder\.py/ nocase ascii wide
                        $string15 = /\/PEASS\-ng\.git/ nocase ascii wide
                        $string16 = "/PEASS-ng/" nocase ascii wide
                        $string17 = /\[\+\]\sBuilding\sGTFOBins\slists/ nocase ascii wide
                        $string18 = /\[\+\]\sBuilding\slinux\sexploit\ssuggesters/
                        $string19 = /\[\+\]\sDownloading\sFat\sLinpeas\sbinaries/ nocase ascii wide
                        $string20 = /\\PEASS\-ng/ nocase ascii wide
                        $string21 = /\\winPEAS\.sln/ nocase ascii wide
                        $string22 = /\\winPEASexe\\/ nocase ascii wide
                        $string23 = "66AA4619-4D0F-4226-9D96-298870E9BB50" nocase ascii wide
                        $string24 = "builder/linpeas_parts/" nocase ascii wide
                        $string25 = "D934058E-A7DB-493F-A741-AE8E3DF867F4" nocase ascii wide
                        $string26 = /gather\/peass\.rb/ nocase ascii wide
                        $string27 = /linpeas_builder\.py/ nocase ascii wide
                        $string28 = "linpeas_darwin_amd64"
                        $string29 = "linpeas_darwin_arm64"
                        $string30 = /linpeas_fat\.sh/ nocase ascii wide
                        $string31 = "linpeas_linux_386"
                        $string32 = "linpeas_linux_amd64"
                        $string33 = "linpeas_linux_arm64"
                        $string34 = /metasploit\/peass\.rb/ nocase ascii wide
                        $string35 = "PEASS-ng-master" nocase ascii wide
                        $string36 = /winPEAS\.bat/ nocase ascii wide
                        $string37 = /WinPEAS\.exe/ nocase ascii wide
                        $string38 = /winPEAS\.ps1/ nocase ascii wide
                        $string39 = /winPEASany\.exe/ nocase ascii wide
                        $string40 = /winPEASany_ofs\.exe/ nocase ascii wide
                        $string41 = "winPEAS-Obfuscated" nocase ascii wide
                        $string42 = "winPEASps1" nocase ascii wide
                        $string43 = /winPEASx64\.exe/ nocase ascii wide
                        $string44 = /winPEASx64_ofs\.exe/ nocase ascii wide
                        $string45 = /winPEASx86\.exe/ nocase ascii wide
                        $string46 = /winPEASx86_ofs\.exe/ nocase ascii wide
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