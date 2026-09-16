rule Striker
{
    meta:
        description = "Detection patterns for the tool 'Striker' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Striker"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\.\/redirector\.py\s/
                        $string2 = /\.striker\.local/ nocase ascii wide
                        $string3 = "/agent/C/src/" nocase ascii wide
                        $string4 = /\/redirector\/redirector\.py/ nocase ascii wide
                        $string5 = "/sites-available/striker" nocase ascii wide
                        $string6 = "/sites-enabled/striker" nocase ascii wide
                        $string7 = /\/striker\.c/ nocase ascii wide
                        $string8 = /\/Striker\.git/ nocase ascii wide
                        $string9 = /\/striker\.local/ nocase ascii wide
                        $string10 = "4g3nt47/Striker" nocase ascii wide
                        $string11 = "bin/striker" nocase ascii wide
                        $string12 = /c2\.striker\./ nocase ascii wide
                        $string13 = /localhost\:3000.{0,1000}striker/ nocase ascii wide
                        $string14 = /nginx\/striker\.log/ nocase ascii wide
                        $string15 = /s0md3v.{0,1000}Striker/ nocase ascii wide
                        $string16 = /src\/obfuscator\.c/ nocase ascii wide
                        $string17 = "VITE_STRIKER_API" nocase ascii wide

    condition:
        any of them
}