rule ASPJinjaObfuscator
{
    meta:
        description = "Detection patterns for the tool 'ASPJinjaObfuscator' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ASPJinjaObfuscator"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "# Add random newlines to the obfuscated code" nocase ascii wide
                        $string2 = /\/ASPJinjaObfuscator\.git/ nocase ascii wide
                        $string3 = /\\ASPJinjaObfuscator/ nocase ascii wide
                        $string4 = "09855e8685bbec09962affefbfad2c554d434a87aca1e1ac8c961f5ebfe6cdad" nocase ascii wide
                        $string5 = /add_random_newlines\(obfuscated_code/ nocase ascii wide
                        $string6 = /asp\-jinja\-obfuscator\.py/ nocase ascii wide
                        $string7 = /encode_base64\(xor_encrypt\(\\"cmd\s\/c\s/ nocase ascii wide
                        $string8 = /encode_base64\(xor_encrypt\(\\"WScript\.Shell\\"/ nocase ascii wide
                        $string9 = "fin3ss3g0d/ASPJinjaObfuscator" nocase ascii wide
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