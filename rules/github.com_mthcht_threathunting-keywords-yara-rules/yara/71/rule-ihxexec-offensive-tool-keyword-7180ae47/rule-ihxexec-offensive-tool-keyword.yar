rule rule_IHxExec_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'IHxExec' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "IHxExec"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_IHxExec_offensive_tool_keyword = /\/IHxExec\.exe/ nocase ascii wide
                        $string2_IHxExec_offensive_tool_keyword = /\/IHxExec\.git/ nocase ascii wide
                        $string3_IHxExec_offensive_tool_keyword = /\/IHxExec\-main\.zip/ nocase ascii wide
                        $string4_IHxExec_offensive_tool_keyword = /\\IHxExec\.cpp/ nocase ascii wide
                        $string5_IHxExec_offensive_tool_keyword = /\\IHxExec\.exe/ nocase ascii wide
                        $string6_IHxExec_offensive_tool_keyword = /\\IHxExec\.vcxproj/ nocase ascii wide
                        $string7_IHxExec_offensive_tool_keyword = /\\IHxExec\-main/ nocase ascii wide
                        $string8_IHxExec_offensive_tool_keyword = "165a010438ef6f3b9d8dfbb47e486740e5d8235e77d28efb7b7c1b93654f71b4" nocase ascii wide
                        $string9_IHxExec_offensive_tool_keyword = "c0ac59bed2e0208db150069c4d943a73036d03271754075029bc2e41f24bb303" nocase ascii wide
                        $string10_IHxExec_offensive_tool_keyword = "CICADA8-Research/IHxExec" nocase ascii wide
                        $string11_IHxExec_offensive_tool_keyword = "d5092358-f3ab-4712-9c7f-d9ec4390193c" nocase ascii wide
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