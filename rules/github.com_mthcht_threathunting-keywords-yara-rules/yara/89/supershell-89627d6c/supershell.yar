rule supershell
{
    meta:
        description = "Detection patterns for the tool 'supershell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "supershell"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " -a -t titleFixed='Supershell - Inject' -t disableLeaveAlert=true -t disableReconnect=true ssh -J rssh:" nocase ascii wide
                        $string2 = " -a -t titleFixed='Supershell - Shell' -t disableLeaveAlert=true ssh -J rssh:" nocase ascii wide
                        $string3 = /\sSupershell\.tar\.gz/ nocase ascii wide
                        $string4 = "/flask:5000/supershell/" nocase ascii wide
                        $string5 = /\/Supershell\.tar\.gz/ nocase ascii wide
                        $string6 = "/supershell/login/auth" nocase ascii wide
                        $string7 = "/Supershell/releases" nocase ascii wide
                        $string8 = /\\Supershell\.tar\.gz/ nocase ascii wide
                        $string9 = /\\Supershell\\rssh\\pkg\\/ nocase ascii wide
                        $string10 = /\\Supershell\\rssh\\pkg\\/ nocase ascii wide
                        $string11 = "b7671f125bb2ed21d0476a00cfaa9ed6" nocase ascii wide
                        $string12 = "http://shell:7681/token" nocase ascii wide
                        $string13 = "password = 'tdragon6'" nocase ascii wide
                        $string14 = /supershell.{0,1000}winpty\.dll/ nocase ascii wide
                        $string15 = /supershell.{0,1000}winpty\-agent\.exe/ nocase ascii wide
                        $string16 = "tdragon6/Supershell" nocase ascii wide

    condition:
        any of them
}