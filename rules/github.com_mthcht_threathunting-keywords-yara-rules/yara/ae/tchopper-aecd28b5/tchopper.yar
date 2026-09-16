rule Tchopper
{
    meta:
        description = "Detection patterns for the tool 'Tchopper' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Tchopper"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\stmp_payload\.txt/ nocase ascii wide
                        $string2 = "#1 - Smuggling binary via Service DisplayName" nocase ascii wide
                        $string3 = "#2 - Smuggling binary via WMI" nocase ascii wide
                        $string4 = /\/TChopper\.git/ nocase ascii wide
                        $string5 = /\[\+\]\stask\shas\sbeen\screated\ssuccessfully\s\s\.\.\!/ nocase ascii wide
                        $string6 = /\[\-\>\]\ssending\spayload\.\.as\schuncks/ nocase ascii wide
                        $string7 = /\\Public\\chop\.enc/ nocase ascii wide
                        $string8 = /\\TChopper\\chopper\./ nocase ascii wide
                        $string9 = /\\Tchopper\-main\.zip/ nocase ascii wide
                        $string10 = /\\tmp_payload\.txt/ nocase ascii wide
                        $string11 = "chop target username password domain filename chd wmi" nocase ascii wide
                        $string12 = /chopper\.exe\s\-m/ nocase ascii wide
                        $string13 = /chopper\.exe\s\-s/ nocase ascii wide
                        $string14 = /chopper\.exe\s\-w/ nocase ascii wide
                        $string15 = /cmd\.exe\s\/c\spowershell\s\-command\s\\"Get\-Service\s.{0,100}chopper/ nocase ascii wide
                        $string16 = "Data Name=\"ServiceName\">chopper</Data>" nocase ascii wide
                        $string17 = "Data Name=\"ServiceName\">final_seg</Data>" nocase ascii wide
                        $string18 = "Data Name=\"ServiceName\">let me in</Data>" nocase ascii wide
                        $string19 = "lawrenceamer/Tchopper" nocase ascii wide
                        $string20 = "'svc_smuggling'" nocase ascii wide
                        $string21 = "Technique #1 - Chop Chop - Create/delete" nocase ascii wide
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