rule rule_ASPJinjaObfuscator_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ASPJinjaObfuscator' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ASPJinjaObfuscator"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ASPJinjaObfuscator_offensive_tool_keyword = "# Add random newlines to the obfuscated code" nocase ascii wide
                        $string2_ASPJinjaObfuscator_offensive_tool_keyword = /\/ASPJinjaObfuscator\.git/ nocase ascii wide
                        $string3_ASPJinjaObfuscator_offensive_tool_keyword = /\\ASPJinjaObfuscator/ nocase ascii wide
                        $string4_ASPJinjaObfuscator_offensive_tool_keyword = "09855e8685bbec09962affefbfad2c554d434a87aca1e1ac8c961f5ebfe6cdad" nocase ascii wide
                        $string5_ASPJinjaObfuscator_offensive_tool_keyword = /add_random_newlines\(obfuscated_code/ nocase ascii wide
                        $string6_ASPJinjaObfuscator_offensive_tool_keyword = /asp\-jinja\-obfuscator\.py/ nocase ascii wide
                        $string7_ASPJinjaObfuscator_offensive_tool_keyword = /encode_base64\(xor_encrypt\(\\"cmd\s\/c\s/ nocase ascii wide
                        $string8_ASPJinjaObfuscator_offensive_tool_keyword = /encode_base64\(xor_encrypt\(\\"WScript\.Shell\\"/ nocase ascii wide
                        $string9_ASPJinjaObfuscator_offensive_tool_keyword = "fin3ss3g0d/ASPJinjaObfuscator" nocase ascii wide

    condition:
        any of them
}