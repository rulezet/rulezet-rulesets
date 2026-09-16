rule rule_Sunder_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Sunder' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Sunder"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Sunder_offensive_tool_keyword = /\/sunder\.exe/ nocase ascii wide
                        $string2_Sunder_offensive_tool_keyword = /\[PRIVESC\]\sGiving\stoken\sfull\sprivileges\sfor\sPID/ nocase ascii wide
                        $string3_Sunder_offensive_tool_keyword = /\[PRIVESC\]\sStealing\stoken\sfrom\sPID\s/ nocase ascii wide
                        $string4_Sunder_offensive_tool_keyword = /\\sunder\.exe/ nocase ascii wide
                        $string5_Sunder_offensive_tool_keyword = /\\SYSTEM\\CurrentControlSet\\Control\\CI\\Config\\\s\-Name\sVulnerableDriverBlocklistEnable\s0/ nocase ascii wide
                        $string6_Sunder_offensive_tool_keyword = "0296e2ce999e67c76352613a718e11516fe1b0efc3ffdb8918fc999dd76a73a5" nocase ascii wide
                        $string7_Sunder_offensive_tool_keyword = "5a958c89-6327-401c-a214-c89e54855b57" nocase ascii wide
                        $string8_Sunder_offensive_tool_keyword = "643ad690-5c85-4b12-af42-2d31d11657a1" nocase ascii wide
                        $string9_Sunder_offensive_tool_keyword = "c9d9c56c1eb6891ede852ccc96dc343afbd5057ab0451bc75ba7095203f0762a" nocase ascii wide
                        $string10_Sunder_offensive_tool_keyword = "ColeHouston/Sunder" nocase ascii wide
                        $string11_Sunder_offensive_tool_keyword = "d42270ec9fee729c30fd5b96918170c896436b04b863a82d578beff5fd980a6c" nocase ascii wide
                        $string12_Sunder_offensive_tool_keyword = /sc\screate\sdellserv\sbinPath\=C\:\\dbutil_2_3\.sys\stype\=kernel/ nocase ascii wide

    condition:
        any of them
}