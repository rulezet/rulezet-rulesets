rule Coercer
{
    meta:
        description = "Detection patterns for the tool 'Coercer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Coercer"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\scoerce\s\-u\s.{0,100}\s\-p\s.{0,100}\s\-\-listener\-ip/ nocase ascii wide
                        $string2 = /\sCoercer\.py/ nocase ascii wide
                        $string3 = /\sfuzz\s\-u\s.{0,100}\s\-p\s.{0,100}\-\-target/ nocase ascii wide
                        $string4 = " --only-known-exploit-paths" nocase ascii wide
                        $string5 = /\sPodalirius\s\(\@podalirius_\)/ nocase ascii wide
                        $string6 = /\/coercer\.egg\-info/ nocase ascii wide
                        $string7 = /\/Coercer\.git/ nocase ascii wide
                        $string8 = /\/Coercer\.py/ nocase ascii wide
                        $string9 = /\/Coercer\/.{0,100}\.py/ nocase ascii wide
                        $string10 = /\\\\\\\\\.\\\\.{0,100}\\\\.{0,100}\\\\.{0,100}\\\\smile\.txt\\/ nocase ascii wide
                        $string11 = /\\coercer\.exe/ nocase ascii wide
                        $string12 = /\\Coercer\.py/ nocase ascii wide
                        $string13 = "cbbadc6ef65c597a7cd81e6f98758815d35ac0530367d87341dd0618b5c7359b" nocase ascii wide
                        $string14 = "Coercer coerce" nocase ascii wide
                        $string15 = "Coercer fuzz" nocase ascii wide
                        $string16 = "Coercer scan" nocase ascii wide
                        $string17 = /coercer\.core/ nocase ascii wide
                        $string18 = /coercer\.methods/ nocase ascii wide
                        $string19 = /coercer\.models/ nocase ascii wide
                        $string20 = /coercer\.network/ nocase ascii wide
                        $string21 = /coercer\.network\.DCERPCSession/ nocase ascii wide
                        $string22 = /coercer\.network\.smb/ nocase ascii wide
                        $string23 = /Coercer\.py\s/ nocase ascii wide
                        $string24 = /coercer\.structures/ nocase ascii wide
                        $string25 = "coercer/core/loader" nocase ascii wide
                        $string26 = "find_and_load_coerce_methods" nocase ascii wide
                        $string27 = "generate_exploit_path_from_template" nocase ascii wide
                        $string28 = "install coercer" nocase ascii wide
                        $string29 = "p0dalirius/Coercer" nocase ascii wide
                        $string30 = "pip install coercer" nocase ascii wide
                        $string31 = /podalirius\@protonmail\.com/ nocase ascii wide
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