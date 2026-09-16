rule Nuages
{
    meta:
        description = "Detection patterns for the tool 'Nuages' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Nuages"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\snuages\.formatImplantLastSeen/ nocase ascii wide
                        $string2 = " NuagesImplant" nocase ascii wide
                        $string3 = "!autoruns " nocase ascii wide
                        $string4 = "!files upload " nocase ascii wide
                        $string5 = "!handlers load " nocase ascii wide
                        $string6 = "!implants " nocase ascii wide
                        $string7 = "!modules load " nocase ascii wide
                        $string8 = /\!put\s.{0,100}\/tmp/ nocase ascii wide
                        $string9 = "!tunnels --tcp" nocase ascii wide
                        $string10 = /\!use\s.{0,100}aes256_py/ nocase ascii wide
                        $string11 = /\!use\s.{0,100}reflected_assembly/ nocase ascii wide
                        $string12 = "/implant/callback" nocase ascii wide
                        $string13 = "/Nuages_Cli" nocase ascii wide
                        $string14 = /\/nuagesAPI\.js/ nocase ascii wide
                        $string15 = /\\Nuages_Cli/ nocase ascii wide
                        $string16 = "before-create-implant-callback" nocase ascii wide
                        $string17 = "before-create-implant-io-bin" nocase ascii wide
                        $string18 = "before-find-implant-chunks" nocase ascii wide
                        $string19 = /DNSAES256Handler\./ nocase ascii wide
                        $string20 = /http.{0,100}127\.0\.0\.1\:3030/ nocase ascii wide
                        $string21 = /http.{0,100}localhost\:3030/ nocase ascii wide
                        $string22 = /HTTPAES256Handler\./ nocase ascii wide
                        $string23 = /implant\-callback\./ nocase ascii wide
                        $string24 = /Nuages.{0,100}\/Implants/ nocase ascii wide
                        $string25 = /nuages\.clearImplants\s/ nocase ascii wide
                        $string26 = /nuages\.getAutoruns/ nocase ascii wide
                        $string27 = /nuages\.getImplants/ nocase ascii wide
                        $string28 = /nuages\.getListeners/ nocase ascii wide
                        $string29 = /nuages\.printImplants/ nocase ascii wide
                        $string30 = /nuages\.printListeners/ nocase ascii wide
                        $string31 = /nuages_cli\.js/ nocase ascii wide
                        $string32 = "NuagesC2Connector" nocase ascii wide
                        $string33 = "NuagesC2Implant" nocase ascii wide
                        $string34 = "NuagesPythonImplant" nocase ascii wide
                        $string35 = "NuagesSharpImplant" nocase ascii wide
                        $string36 = "p3nt4/Nuages" nocase ascii wide
                        $string37 = "posh_in_mem" nocase ascii wide
                        $string38 = "processImplantMessage" nocase ascii wide
                        $string39 = "runFakeTerminal" nocase ascii wide
                        $string40 = /SLACKAES256Handler\./ nocase ascii wide
                        $string41 = /Utils\\Posh\.cs/ nocase ascii wide
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