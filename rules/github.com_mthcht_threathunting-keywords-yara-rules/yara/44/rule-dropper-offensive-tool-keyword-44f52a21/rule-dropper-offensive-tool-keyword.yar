rule rule_dropper_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'dropper' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dropper"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_dropper_offensive_tool_keyword = /\/Chakra\.dll/ nocase ascii wide
                        $string2_dropper_offensive_tool_keyword = /\[\+\]\sInjecting\sdropper\.vba\sinto\s/ nocase ascii wide
                        $string3_dropper_offensive_tool_keyword = /\\Chakra\.dll/ nocase ascii wide
                        $string4_dropper_offensive_tool_keyword = /\\Demo\\VulnApp\.exe/ nocase ascii wide
                        $string5_dropper_offensive_tool_keyword = /\\dropper\\dropit\.py/ nocase ascii wide
                        $string6_dropper_offensive_tool_keyword = /\\dropper\\dropper\.vba/ nocase ascii wide
                        $string7_dropper_offensive_tool_keyword = /\\tools\\DocLnk\.exe/ nocase ascii wide
                        $string8_dropper_offensive_tool_keyword = "441cb40ecc946bfb7d9ec0e7880f17f07b899adb176c6f40231aec2ab41ac1d7" nocase ascii wide
                        $string9_dropper_offensive_tool_keyword = "62ad0c68652b614acd4b82670b987719dee83f900678788bacf7cef174ea17d9" nocase ascii wide
                        $string10_dropper_offensive_tool_keyword = "a475f8e5b3581cb7b93cd3021478957ec5997aa3995c1a686fb87ae6c84ec2b1" nocase ascii wide
                        $string11_dropper_offensive_tool_keyword = "c27eaa1709a00ec0c47d47b8c6c061b2f63223d8553fa7d7baa40f7cea903b8f" nocase ascii wide
                        $string12_dropper_offensive_tool_keyword = "c6e09870a9f7d1e74d9364d7a4d27cc0ad96f1637ee3e60e2c2df5169972058c" nocase ascii wide
                        $string13_dropper_offensive_tool_keyword = /execute_embed_docm\(/ nocase ascii wide
                        $string14_dropper_offensive_tool_keyword = /genMalDoc\(\)/ nocase ascii wide
                        $string15_dropper_offensive_tool_keyword = /github.{0,1000}\/dropper\.git/ nocase ascii wide
                        $string16_dropper_offensive_tool_keyword = "Hello from Malicious DLL" nocase ascii wide
                        $string17_dropper_offensive_tool_keyword = /inject_macro_word\(/ nocase ascii wide
                        $string18_dropper_offensive_tool_keyword = "SaadAhla/dropper" nocase ascii wide
                        $string19_dropper_offensive_tool_keyword = /update_vba_file_url_droppingPath\(/ nocase ascii wide

    condition:
        any of them
}