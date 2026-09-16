rule ntdlll_unhooking_collection
{
    meta:
        description = "Detection patterns for the tool 'ntdlll-unhooking-collection' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ntdlll-unhooking-collection"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/ntdlll-unhooking-collection" nocase ascii wide
                        $string2 = /\\ntdlll\-unhooking\-collection/ nocase ascii wide
                        $string3 = "0472A393-9503-491D-B6DA-FA47CD567EDE" nocase ascii wide
                        $string4 = "1C5EDA8C-D27F-44A4-A156-6F863477194D" nocase ascii wide
                        $string5 = "4DE43724-3851-4376-BB6C-EA15CF500C44" nocase ascii wide
                        $string6 = "DA230B64-14EA-4D49-96E1-FA5EFED9010B" nocase ascii wide
                        $string7 = /Ntdll_SusProcess\./ nocase ascii wide
                        $string8 = /RemoteNTDLL\.cpp/ nocase ascii wide
                        $string9 = /RemoteNTDLL\.exe/ nocase ascii wide
                        $string10 = /UnhookingKnownDlls\./ nocase ascii wide
                        $string11 = /UnhookingNtdll_disk\./ nocase ascii wide
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