rule rule_EarthWorm_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'EarthWorm' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EarthWorm"
        rule_category = "signature_keyword"

    strings:
                        $string1_EarthWorm_signature_keyword = "ELF:Earthworm-B" nocase ascii wide
                        $string2_EarthWorm_signature_keyword = /HackTool\.EarthWorm/ nocase ascii wide
                        $string3_EarthWorm_signature_keyword = /Hacktool\.Earthworm/ nocase ascii wide
                        $string4_EarthWorm_signature_keyword = /HackTool\.Linux\.EarthWorm/ nocase ascii wide
                        $string5_EarthWorm_signature_keyword = /HackTool\.Win32\.Earthworm/ nocase ascii wide
                        $string6_EarthWorm_signature_keyword = /HackTool\/Win32\.Earthworm/ nocase ascii wide
                        $string7_EarthWorm_signature_keyword = "HackTool:Linux/EarthWorm" nocase ascii wide
                        $string8_EarthWorm_signature_keyword = /Linux\.Hacktool\.Earthworm/ nocase ascii wide
                        $string9_EarthWorm_signature_keyword = /Tool\.Linux\.EarthWorm/ nocase ascii wide
                        $string10_EarthWorm_signature_keyword = /Win\.Tool\.Earthworm\-/ nocase ascii wide
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