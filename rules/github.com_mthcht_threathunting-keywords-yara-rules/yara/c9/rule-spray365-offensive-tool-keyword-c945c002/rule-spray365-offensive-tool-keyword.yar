rule rule_Spray365_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Spray365' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Spray365"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Spray365_offensive_tool_keyword = " --custom_user_agent" nocase ascii wide
                        $string2_Spray365_offensive_tool_keyword = /\sgenerate\saudit\s\-ep\s.{0,1000}\-\-passwords_in_userfile/ nocase ascii wide
                        $string3_Spray365_offensive_tool_keyword = /\sgenerate\snormal\s\-ep\s.{0,1000}\s\-d\s.{0,1000}\s\-u\s.{0,1000}\s\-pf\s/ nocase ascii wide
                        $string4_Spray365_offensive_tool_keyword = /\sgenerate\snormal\s\-ep\sex\-plan\.s365\s/ nocase ascii wide
                        $string5_Spray365_offensive_tool_keyword = " --random_user_agent" nocase ascii wide
                        $string6_Spray365_offensive_tool_keyword = " --show_invalid_creds" nocase ascii wide
                        $string7_Spray365_offensive_tool_keyword = /\sspray\s\-ep\sex\-plan\.s365/ nocase ascii wide
                        $string8_Spray365_offensive_tool_keyword = /\.py\sspray\s\-ep\s/ nocase ascii wide
                        $string9_Spray365_offensive_tool_keyword = /\/spray\/spray\.py/ nocase ascii wide
                        $string10_Spray365_offensive_tool_keyword = "/Spray365" nocase ascii wide
                        $string11_Spray365_offensive_tool_keyword = /Spray365\.git/ nocase ascii wide
                        $string12_Spray365_offensive_tool_keyword = /spray365\.py/ nocase ascii wide
                        $string13_Spray365_offensive_tool_keyword = /spray365_results_.{0,1000}\.json/ nocase ascii wide
                        $string14_Spray365_offensive_tool_keyword = /\-\-user_file.{0,1000}\-\-password_file/ nocase ascii wide

    condition:
        any of them
}