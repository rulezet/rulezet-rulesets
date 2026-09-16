rule WMEye
{
    meta:
        description = "Detection patterns for the tool 'WMEye' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WMEye"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/WMEye\.git/ nocase ascii wide
                        $string2 = "/wmeye/" nocase ascii wide
                        $string3 = /\[X\]\sShellCode\sProperty\sCreated/ nocase ascii wide
                        $string4 = /\[X\]\sUploading\sShellcode\sinto\starget/ nocase ascii wide
                        $string5 = /\\wmeye\.csproj/ nocase ascii wide
                        $string6 = /\\wmeye\.pdb/ nocase ascii wide
                        $string7 = "080de56a40e4ff15b0157da0224988a36f3e7c2347d58824ab3880f338d3eaec" nocase ascii wide
                        $string8 = "928120DC-5275-4806-B99B-12D67B710DC0" nocase ascii wide
                        $string9 = "namespace WmEye" nocase ascii wide
                        $string10 = "OiCAAAAYInlMcBki1Awi1IMi1IUi3IoD7dKJjH/rDxhfAIsIMHPDQHH4vJSV4tSEItKPItMEXjjSAHRUYtZIAHTi0kY4zpJizSLAdYx" nocase ascii wide
                        $string11 = "public class WmEye" nocase ascii wide
                        $string12 = "pwn1sher/WMEye" nocase ascii wide
                        $string13 = /wmeye\.csproj/ nocase ascii wide
                        $string14 = /wmeye\.exe\s/ nocase ascii wide
                        $string15 = /wmeye\.sln/ nocase ascii wide
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