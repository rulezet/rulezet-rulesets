rule rule_Forensike_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Forensike' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Forensike"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Forensike_offensive_tool_keyword = " -c \"!mimikatz\" " nocase ascii wide
                        $string2_Forensike_offensive_tool_keyword = /\sForensike\.ps1/ nocase ascii wide
                        $string3_Forensike_offensive_tool_keyword = /\$dumpDir\\lsass\.txt/ nocase ascii wide
                        $string4_Forensike_offensive_tool_keyword = /\$ForensikeFolder/ nocase ascii wide
                        $string5_Forensike_offensive_tool_keyword = /\/DumpIt\.exe/ nocase ascii wide
                        $string6_Forensike_offensive_tool_keyword = /\/Forensike\.git/ nocase ascii wide
                        $string7_Forensike_offensive_tool_keyword = /\/Forensike\.ps1/ nocase ascii wide
                        $string8_Forensike_offensive_tool_keyword = /\/mimilib\.dll/ nocase ascii wide
                        $string9_Forensike_offensive_tool_keyword = /\\DumpIt\.exe/ nocase ascii wide
                        $string10_Forensike_offensive_tool_keyword = /\\Forensike\.dmp/ nocase ascii wide
                        $string11_Forensike_offensive_tool_keyword = /\\Forensike\.ps1/ nocase ascii wide
                        $string12_Forensike_offensive_tool_keyword = /\\forensike_results\.txt/ nocase ascii wide
                        $string13_Forensike_offensive_tool_keyword = /\\mimilib\.dll/ nocase ascii wide
                        $string14_Forensike_offensive_tool_keyword = /\\Windows\\Temp\\Forensike/ nocase ascii wide
                        $string15_Forensike_offensive_tool_keyword = /\>\[\sSTARTING\sCRASH\sDUMP\sACQUISITION\s\]\</ nocase ascii wide
                        $string16_Forensike_offensive_tool_keyword = /\>\[\sSTARTING\sNT\sHASHES\sEXTRACTION\s\]\</ nocase ascii wide
                        $string17_Forensike_offensive_tool_keyword = "6a484c1db7718949c7027abde97e164c7e7e4e4214e3e29fe48ac4364c0cd23c" nocase ascii wide
                        $string18_Forensike_offensive_tool_keyword = "7ffce7f6d7262f214d78e6b7fd8d07119835cba4b04ce334260665d7c8fb369a" nocase ascii wide
                        $string19_Forensike_offensive_tool_keyword = "bmarchev/Forensike" nocase ascii wide
                        $string20_Forensike_offensive_tool_keyword = "e81284fcd76acab65fcb296db056f50a4fa61eb120581ff2d494006d97f2f762" nocase ascii wide
                        $string21_Forensike_offensive_tool_keyword = "load mimikatz windbg extension, extracts credential from crash dump" nocase ascii wide
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