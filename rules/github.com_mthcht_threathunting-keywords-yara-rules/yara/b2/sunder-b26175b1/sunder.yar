rule Sunder
{
    meta:
        description = "Detection patterns for the tool 'Sunder' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Sunder"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/sunder\.exe/ nocase ascii wide
                        $string2 = /\[PRIVESC\]\sGiving\stoken\sfull\sprivileges\sfor\sPID/ nocase ascii wide
                        $string3 = /\[PRIVESC\]\sStealing\stoken\sfrom\sPID\s/ nocase ascii wide
                        $string4 = /\\sunder\.exe/ nocase ascii wide
                        $string5 = /\\SYSTEM\\CurrentControlSet\\Control\\CI\\Config\\\s\-Name\sVulnerableDriverBlocklistEnable\s0/ nocase ascii wide
                        $string6 = "0296e2ce999e67c76352613a718e11516fe1b0efc3ffdb8918fc999dd76a73a5" nocase ascii wide
                        $string7 = "5a958c89-6327-401c-a214-c89e54855b57" nocase ascii wide
                        $string8 = "643ad690-5c85-4b12-af42-2d31d11657a1" nocase ascii wide
                        $string9 = "c9d9c56c1eb6891ede852ccc96dc343afbd5057ab0451bc75ba7095203f0762a" nocase ascii wide
                        $string10 = "ColeHouston/Sunder" nocase ascii wide
                        $string11 = "d42270ec9fee729c30fd5b96918170c896436b04b863a82d578beff5fd980a6c" nocase ascii wide
                        $string12 = /sc\screate\sdellserv\sbinPath\=C\:\\dbutil_2_3\.sys\stype\=kernel/ nocase ascii wide
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
            uint16(0) == 0x5a4d or             uint16(0) == 0x457f or             uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or             uint32(0) == 0x504B0304 or             uint32(0) == 0xCAFEBABE or             uint32(0) == 0x4D534346 or             uint32(0) == 0xD0CF11E0 or             uint16(0) == 0x2321 or             uint16(0) == 0x3c3f         )) and any of ($string*)) or
        (filesize < 2MB and
        (
            any of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}