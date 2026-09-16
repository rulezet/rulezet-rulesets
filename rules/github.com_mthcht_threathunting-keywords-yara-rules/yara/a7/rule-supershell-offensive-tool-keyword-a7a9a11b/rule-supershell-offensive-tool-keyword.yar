rule rule_supershell_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'supershell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "supershell"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_supershell_offensive_tool_keyword = " -a -t titleFixed='Supershell - Inject' -t disableLeaveAlert=true -t disableReconnect=true ssh -J rssh:" nocase ascii wide
                        $string2_supershell_offensive_tool_keyword = " -a -t titleFixed='Supershell - Shell' -t disableLeaveAlert=true ssh -J rssh:" nocase ascii wide
                        $string3_supershell_offensive_tool_keyword = /\sSupershell\.tar\.gz/ nocase ascii wide
                        $string4_supershell_offensive_tool_keyword = "/flask:5000/supershell/" nocase ascii wide
                        $string5_supershell_offensive_tool_keyword = /\/Supershell\.tar\.gz/ nocase ascii wide
                        $string6_supershell_offensive_tool_keyword = "/supershell/login/auth" nocase ascii wide
                        $string7_supershell_offensive_tool_keyword = "/Supershell/releases" nocase ascii wide
                        $string8_supershell_offensive_tool_keyword = /\\Supershell\.tar\.gz/ nocase ascii wide
                        $string9_supershell_offensive_tool_keyword = /\\Supershell\\rssh\\pkg\\/ nocase ascii wide
                        $string10_supershell_offensive_tool_keyword = /\\Supershell\\rssh\\pkg\\/ nocase ascii wide
                        $string11_supershell_offensive_tool_keyword = "b7671f125bb2ed21d0476a00cfaa9ed6" nocase ascii wide
                        $string12_supershell_offensive_tool_keyword = "http://shell:7681/token" nocase ascii wide
                        $string13_supershell_offensive_tool_keyword = "password = 'tdragon6'" nocase ascii wide
                        $string14_supershell_offensive_tool_keyword = /supershell.{0,1000}winpty\.dll/ nocase ascii wide
                        $string15_supershell_offensive_tool_keyword = /supershell.{0,1000}winpty\-agent\.exe/ nocase ascii wide
                        $string16_supershell_offensive_tool_keyword = "tdragon6/Supershell" nocase ascii wide

    condition:
        any of them
}