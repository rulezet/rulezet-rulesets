rule Phant0m
{
    meta:
        description = "Detection patterns for the tool 'Phant0m' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Phant0m"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/Phant0m\.git/ nocase ascii wide
                        $string2 = "/phant0m-exe" nocase ascii wide
                        $string3 = /\\wmi_1\.dll/ nocase ascii wide
                        $string4 = /\\wmi_2\.dll/ nocase ascii wide
                        $string5 = "hlldz/Phant0m" nocase ascii wide
                        $string6 = /Invoke\-Phant0m\.ps1/ nocase ascii wide
                        $string7 = "Phant0m scm 1" nocase ascii wide
                        $string8 = "Phant0m scm 2" nocase ascii wide
                        $string9 = "Phant0m wmi" nocase ascii wide
                        $string10 = /phant0m\.cna/ nocase ascii wide
                        $string11 = /phant0m\-exe\./ nocase ascii wide
                        $string12 = /Phant0m\-master\.zip/ nocase ascii wide
                        $string13 = "phant0m-rdll" nocase ascii wide

    condition:
        any of them
}