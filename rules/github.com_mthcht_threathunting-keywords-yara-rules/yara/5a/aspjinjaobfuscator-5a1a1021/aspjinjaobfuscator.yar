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

    condition:
        any of them
}