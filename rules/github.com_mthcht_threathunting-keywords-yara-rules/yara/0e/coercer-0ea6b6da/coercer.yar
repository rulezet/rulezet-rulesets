rule Coercer
{
    meta:
        description = "Detection patterns for the tool 'Coercer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Coercer"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\scoerce\s\-u\s.{0,1000}\s\-p\s.{0,1000}\s\-\-listener\-ip/ nocase ascii wide
                        $string2 = /\sCoercer\.py/ nocase ascii wide
                        $string3 = /\sfuzz\s\-u\s.{0,1000}\s\-p\s.{0,1000}\-\-target/ nocase ascii wide
                        $string4 = " --only-known-exploit-paths" nocase ascii wide
                        $string5 = /\sPodalirius\s\(\@podalirius_\)/ nocase ascii wide
                        $string6 = /\/coercer\.egg\-info/ nocase ascii wide
                        $string7 = /\/Coercer\.git/ nocase ascii wide
                        $string8 = /\/Coercer\.py/ nocase ascii wide
                        $string9 = /\/Coercer\/.{0,1000}\.py/ nocase ascii wide
                        $string10 = /\\\\\\\\\.\\\\.{0,1000}\\\\.{0,1000}\\\\.{0,1000}\\\\smile\.txt\\/ nocase ascii wide
                        $string11 = /\\coercer\.exe/ nocase ascii wide
                        $string12 = /\\Coercer\.py/ nocase ascii wide
                        $string13 = "cbbadc6ef65c597a7cd81e6f98758815d35ac0530367d87341dd0618b5c7359b" nocase ascii wide
                        $string14 = "Coercer coerce" nocase ascii wide
                        $string15 = "Coercer fuzz" nocase ascii wide
                        $string16 = "Coercer scan" nocase ascii wide
                        $string17 = /coercer\.core/ nocase ascii wide
                        $string18 = /coercer\.methods/ nocase ascii wide
                        $string19 = /coercer\.models/ nocase ascii wide
                        $string20 = /coercer\.network/ nocase ascii wide
                        $string21 = /coercer\.network\.DCERPCSession/ nocase ascii wide
                        $string22 = /coercer\.network\.smb/ nocase ascii wide
                        $string23 = /Coercer\.py\s/ nocase ascii wide
                        $string24 = /coercer\.structures/ nocase ascii wide
                        $string25 = "coercer/core/loader" nocase ascii wide
                        $string26 = "find_and_load_coerce_methods" nocase ascii wide
                        $string27 = "generate_exploit_path_from_template" nocase ascii wide
                        $string28 = "install coercer" nocase ascii wide
                        $string29 = "p0dalirius/Coercer" nocase ascii wide
                        $string30 = "pip install coercer" nocase ascii wide
                        $string31 = /podalirius\@protonmail\.com/ nocase ascii wide

    condition:
        any of them
}