rule Spray365
{
    meta:
        description = "Detection patterns for the tool 'Spray365' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Spray365"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " --custom_user_agent" nocase ascii wide
                        $string2 = /\sgenerate\saudit\s\-ep\s.{0,1000}\-\-passwords_in_userfile/ nocase ascii wide
                        $string3 = /\sgenerate\snormal\s\-ep\s.{0,1000}\s\-d\s.{0,1000}\s\-u\s.{0,1000}\s\-pf\s/ nocase ascii wide
                        $string4 = /\sgenerate\snormal\s\-ep\sex\-plan\.s365\s/ nocase ascii wide
                        $string5 = " --random_user_agent" nocase ascii wide
                        $string6 = " --show_invalid_creds" nocase ascii wide
                        $string7 = /\sspray\s\-ep\sex\-plan\.s365/ nocase ascii wide
                        $string8 = /\.py\sspray\s\-ep\s/ nocase ascii wide
                        $string9 = /\/spray\/spray\.py/ nocase ascii wide
                        $string10 = "/Spray365" nocase ascii wide
                        $string11 = /Spray365\.git/ nocase ascii wide
                        $string12 = /spray365\.py/ nocase ascii wide
                        $string13 = /spray365_results_.{0,1000}\.json/ nocase ascii wide
                        $string14 = /\-\-user_file.{0,1000}\-\-password_file/ nocase ascii wide

    condition:
        any of them
}