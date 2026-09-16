rule Venom
{
    meta:
        description = "Detection patterns for the tool 'Venom' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Venom"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sport_reuse\.py/ nocase ascii wide
                        $string2 = " --string 'venomcoming' " nocase ascii wide
                        $string3 = " --string 'venomleaving' " nocase ascii wide
                        $string4 = /\/port_reuse\.py/ nocase ascii wide
                        $string5 = /\/Venom\.git/ nocase ascii wide
                        $string6 = /\/Venom\.v1\.0\.1\.7z/ nocase ascii wide
                        $string7 = /\/Venom\.v1\.0\.2\.7z/ nocase ascii wide
                        $string8 = /\/Venom\.v1\.0\.7z/ nocase ascii wide
                        $string9 = /\/Venom\.v1\.1\.0\.7z/ nocase ascii wide
                        $string10 = "/Venom/tarball/v" nocase ascii wide
                        $string11 = "/Venom/zipball/v" nocase ascii wide
                        $string12 = /\\port_reuse\.py/ nocase ascii wide
                        $string13 = /\\Venom\.v1\.0\.1\.7z/ nocase ascii wide
                        $string14 = /\\Venom\.v1\.0\.2\.7z/ nocase ascii wide
                        $string15 = /\\Venom\.v1\.0\.7z/ nocase ascii wide
                        $string16 = /\\Venom\.v1\.1\.0\.7z/ nocase ascii wide
                        $string17 = "37da8267b295caeca8fadb13206ba1c498a7012673430c5d856fe93862446a28" nocase ascii wide
                        $string18 = "52907aebc7d2c6534099d149e61bf294b0ddf7d4e814a72b3621e3a829f83c97" nocase ascii wide
                        $string19 = /admin_macos_x64\s\-rhost\s.{0,1000}\s\-rport\s/ nocase ascii wide
                        $string20 = /agent\.exe\s\-lhost\s.{0,1000}\s\-reuse\-port\s/ nocase ascii wide
                        $string21 = "agent_linux_x64 -lport "
                        $string22 = /agent_linux_x64\s\-rhost\s.{0,1000}\s\-rport\s/
                        $string23 = "Venom Admin Node Start" nocase ascii wide
                        $string24 = /Venom\\agent\\agent\.go/ nocase ascii wide
                        $string25 = "You can execute commands in this shell :D" nocase ascii wide

    condition:
        any of them
}