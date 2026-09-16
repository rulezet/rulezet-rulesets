rule rule_Ddexec_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Ddexec' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Ddexec"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Ddexec_offensive_tool_keyword = /\sbash\sddexec\.sh/
                        $string2_Ddexec_offensive_tool_keyword = /\sddexec\.sh\s/
                        $string3_Ddexec_offensive_tool_keyword = /\sddsc\.sh\s\-x/
                        $string4_Ddexec_offensive_tool_keyword = /\szsh\sddexec\.sh/
                        $string5_Ddexec_offensive_tool_keyword = /\/DDexec\.git/
                        $string6_Ddexec_offensive_tool_keyword = /\/ddexec\.sh/
                        $string7_Ddexec_offensive_tool_keyword = /\/ddsc\.sh\s/
                        $string8_Ddexec_offensive_tool_keyword = "4109aabda29898f764177befbe6967500dd724e511317a8232a046c91502b38f"
                        $string9_Ddexec_offensive_tool_keyword = "955201aaf535183bd7a881278fbaab7a16f742c150ff44e1d7ab0325c0c03baf"
                        $string10_Ddexec_offensive_tool_keyword = "arget13/DDexec"
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