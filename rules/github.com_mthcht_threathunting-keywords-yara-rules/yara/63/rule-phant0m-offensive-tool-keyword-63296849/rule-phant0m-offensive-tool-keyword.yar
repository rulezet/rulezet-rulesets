rule rule_Phant0m_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Phant0m' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Phant0m"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Phant0m_offensive_tool_keyword = /\/Phant0m\.git/ nocase ascii wide
                        $string2_Phant0m_offensive_tool_keyword = "/phant0m-exe" nocase ascii wide
                        $string3_Phant0m_offensive_tool_keyword = /\\wmi_1\.dll/ nocase ascii wide
                        $string4_Phant0m_offensive_tool_keyword = /\\wmi_2\.dll/ nocase ascii wide
                        $string5_Phant0m_offensive_tool_keyword = "hlldz/Phant0m" nocase ascii wide
                        $string6_Phant0m_offensive_tool_keyword = /Invoke\-Phant0m\.ps1/ nocase ascii wide
                        $string7_Phant0m_offensive_tool_keyword = "Phant0m scm 1" nocase ascii wide
                        $string8_Phant0m_offensive_tool_keyword = "Phant0m scm 2" nocase ascii wide
                        $string9_Phant0m_offensive_tool_keyword = "Phant0m wmi" nocase ascii wide
                        $string10_Phant0m_offensive_tool_keyword = /phant0m\.cna/ nocase ascii wide
                        $string11_Phant0m_offensive_tool_keyword = /phant0m\-exe\./ nocase ascii wide
                        $string12_Phant0m_offensive_tool_keyword = /Phant0m\-master\.zip/ nocase ascii wide
                        $string13_Phant0m_offensive_tool_keyword = "phant0m-rdll" nocase ascii wide

    condition:
        any of them
}