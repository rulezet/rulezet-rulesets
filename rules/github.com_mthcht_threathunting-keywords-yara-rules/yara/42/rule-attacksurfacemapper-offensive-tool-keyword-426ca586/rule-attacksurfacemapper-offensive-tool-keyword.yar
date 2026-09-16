rule rule_AttackSurfaceMapper_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'AttackSurfaceMapper' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AttackSurfaceMapper"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_AttackSurfaceMapper_offensive_tool_keyword = /\sasm\.py\s\-t\s.{0,100}\s\-ln\s\-w\sresources\/.{0,100}\.txt\s\-o\s/ nocase ascii wide
                        $string2_AttackSurfaceMapper_offensive_tool_keyword = /\/AttackSurfaceMapper\.git/ nocase ascii wide
                        $string3_AttackSurfaceMapper_offensive_tool_keyword = /\/email_spoof_checks\.txt/
                        $string4_AttackSurfaceMapper_offensive_tool_keyword = /\/guessed_emails\.txt/
                        $string5_AttackSurfaceMapper_offensive_tool_keyword = "AttackSurfaceMapper-master" nocase ascii wide
                        $string6_AttackSurfaceMapper_offensive_tool_keyword = /bitquark_top100k_sublist\.txt/ nocase ascii wide
                        $string7_AttackSurfaceMapper_offensive_tool_keyword = /commonspeak_sublist\.txt/ nocase ascii wide
                        $string8_AttackSurfaceMapper_offensive_tool_keyword = "superhedgy/AttackSurfaceMapper" nocase ascii wide
                        $string9_AttackSurfaceMapper_offensive_tool_keyword = /top100_sublist\.txt/ nocase ascii wide
                        $string10_AttackSurfaceMapper_offensive_tool_keyword = /top1000_sublist\.txt/ nocase ascii wide
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