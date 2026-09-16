rule rule_decrypt_chrome_passwords_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'decrypt-chrome-passwords' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "decrypt-chrome-passwords"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_decrypt_chrome_passwords_offensive_tool_keyword = "/decrypt-chrome-passwords" nocase ascii wide
                        $string2_decrypt_chrome_passwords_offensive_tool_keyword = /decrypt_chrome_password\.py/ nocase ascii wide
                        $string3_decrypt_chrome_passwords_offensive_tool_keyword = "decrypt-chrome-passwords-main" nocase ascii wide

    condition:
        any of them
}