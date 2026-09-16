rule Ammyy_Admin
{
    meta:
        description = "Detection patterns for the tool 'Ammyy Admin' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Ammyy Admin"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\\aa_nts\.dll/ nocase ascii wide
                        $string2 = /\\AA_v3\.exe/ nocase ascii wide
                        $string3 = /\\AA_v3\.log/ nocase ascii wide
                        $string4 = /\\AMMYY\\access\.log/ nocase ascii wide
                        $string5 = /\\ControlSet001\\Control\\SafeBoot\\Network\\AmmyyAdmin_/ nocase ascii wide
                        $string6 = /\\ProgramData\\AMMYY\\/ nocase ascii wide
                        $string7 = /\\SOFTWARE\\Ammyy\\Admin/ nocase ascii wide
                        $string8 = /AA_v3\.exe.{0,100}\s\-elevated/ nocase ascii wide
                        $string9 = /AA_v3\.exe.{0,100}\s\-service\s\-lunch/ nocase ascii wide
                        $string10 = "Ammyy Admin" nocase ascii wide
                        $string11 = "Ammyy LLC" nocase ascii wide
                        $string12 = /AMMYY_Admin\.exe/ nocase ascii wide
                        $string13 = /rl\.ammyy\.com\// nocase ascii wide
                        $string14 = /SPR\/Ammyy\.R/ nocase ascii wide
                        $string15 = /Win32\.PUA\.AmmyyAdmin/ nocase ascii wide
                        $string16 = /www\.ammyy\.com\/files\/v/ nocase ascii wide
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