rule Necro_Stealer
{
    meta:
        description = "Detection patterns for the tool 'Necro-Stealer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Necro-Stealer"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/Necro\-Stealer\.git/ nocase ascii wide
                        $string2 = /\\Necro\-Stealer\-.{0,100}\.zip/ nocase ascii wide
                        $string3 = "a568c8a8c28b7ceeee2f5eec82f94dd4fb0fc06175b2ee3043f863a68451ebbd" nocase ascii wide
                        $string4 = "ac3107cf-291c-449b-9121-55cd37f6383e" nocase ascii wide
                        $string5 = "d14be0c5477fc937b2cc00367931e1181d8897ce98a560cff48e0939840a096b" nocase ascii wide
                        $string6 = /NecroStealer\.exe/ nocase ascii wide
                        $string7 = "SecUser1/Necro-Stealer" nocase ascii wide
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