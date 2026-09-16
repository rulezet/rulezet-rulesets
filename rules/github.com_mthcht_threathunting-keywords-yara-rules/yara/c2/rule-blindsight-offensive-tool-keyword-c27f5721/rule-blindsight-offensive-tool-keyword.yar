rule rule_blindsight_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'blindsight' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "blindsight"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_blindsight_offensive_tool_keyword = " - Dump LSASS memory bypassing countermeasures" nocase ascii wide
                        $string2_blindsight_offensive_tool_keyword = /\s29ABE9Hy\.log/ nocase ascii wide
                        $string3_blindsight_offensive_tool_keyword = /\/blindsight\.exe/ nocase ascii wide
                        $string4_blindsight_offensive_tool_keyword = /\/blindsight\.git/ nocase ascii wide
                        $string5_blindsight_offensive_tool_keyword = /\[\+\]\sFound\s\{LSASS\}\spid\:\s\{pid\}/ nocase ascii wide
                        $string6_blindsight_offensive_tool_keyword = /\[\+\]\sSuccessfully\sopened\s\{LSASS\}\shandle/ nocase ascii wide
                        $string7_blindsight_offensive_tool_keyword = /\\blindsight\.exe/ nocase ascii wide
                        $string8_blindsight_offensive_tool_keyword = /\\lsass\.dmp/ nocase ascii wide
                        $string9_blindsight_offensive_tool_keyword = "0xdea/blindsight" nocase ascii wide
                        $string10_blindsight_offensive_tool_keyword = "461356f9bd764b57b3b9a1457aa60494ae73a7935133f5b6122edcb286b7ef0a" nocase ascii wide
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