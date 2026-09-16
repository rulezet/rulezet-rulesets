rule RDE1
{
    meta:
        description = "Detection patterns for the tool 'RDE1' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RDE1"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " crde_arm_musl https -" nocase ascii wide
                        $string2 = " crde_armv7 https -" nocase ascii wide
                        $string3 = " crde_debug https -" nocase ascii wide
                        $string4 = " crde_linux https -"
                        $string5 = " crde_linux_aarch64 https -"
                        $string6 = " crde_linux_x86_64 https -"
                        $string7 = " crde_macos https -" nocase ascii wide
                        $string8 = " crde_release https -" nocase ascii wide
                        $string9 = " crde_windows https -" nocase ascii wide
                        $string10 = " crde_windows_x64 https -" nocase ascii wide
                        $string11 = " crde_windows_x86 https -" nocase ascii wide
                        $string12 = /\shttps\s\-i\s0\.0\.0\.0\s\-P\s.{0,1000}\s\-k\s.{0,1000}\s\-\-private\-cert\s.{0,1000}\s\-\-public\-cert\s/ nocase ascii wide
                        $string13 = " rde1 crde_windows" nocase ascii wide
                        $string14 = " rde1 srde_linux"
                        $string15 = " rde1 srde_macos" nocase ascii wide
                        $string16 = " rde1 srde_windows" nocase ascii wide
                        $string17 = " rec2 crde_linux"
                        $string18 = " rec2 crde_macos" nocase ascii wide
                        $string19 = " srde_arm_musl https -" nocase ascii wide
                        $string20 = " srde_armv7 https -" nocase ascii wide
                        $string21 = " srde_debug https -" nocase ascii wide
                        $string22 = " srde_linux https -"
                        $string23 = " srde_linux_aarch64 https -"
                        $string24 = " srde_linux_x86_64 https -"
                        $string25 = " srde_macos https -" nocase ascii wide
                        $string26 = " srde_release https -" nocase ascii wide
                        $string27 = " srde_windows https -" nocase ascii wide
                        $string28 = " srde_windows_x64 https -" nocase ascii wide
                        $string29 = " srde_windows_x86 https -" nocase ascii wide
                        $string30 = /\/RDE1\.git/ nocase ascii wide
                        $string31 = "crde dns -" nocase ascii wide
                        $string32 = "crde https -" nocase ascii wide
                        $string33 = "crde::utils::checker" nocase ascii wide
                        $string34 = /crde_x64\.exe\sdns\s\-f\s/ nocase ascii wide
                        $string35 = /crde_x64\.exe\shttps\s\-f\s/ nocase ascii wide
                        $string36 = /docker\srun\s.{0,1000}\/usr\/src\/rde1/ nocase ascii wide
                        $string37 = /docker\srun\s.{0,1000}\/usr\/src\/rec2/ nocase ascii wide
                        $string38 = "Exfiltration from DNS finished!" nocase ascii wide
                        $string39 = "Exfiltration from HTTPS finished!" nocase ascii wide
                        $string40 = "g0h4n/RDE1" nocase ascii wide
                        $string41 = "methods::dns::dns_exfiltrator" nocase ascii wide
                        $string42 = "methods::https::https_exfiltrator" nocase ascii wide
                        $string43 = "methods::icmp::icmp_exfiltrator" nocase ascii wide
                        $string44 = /RDE1\-main\.zip/ nocase ascii wide
                        $string45 = "srde dns -" nocase ascii wide
                        $string46 = "srde https -" nocase ascii wide
                        $string47 = "srde_release dns -k " nocase ascii wide
                        $string48 = "srde_release https -i " nocase ascii wide

    condition:
        any of them
}