rule octopus
{
    meta:
        description = "Detection patterns for the tool 'octopus' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "octopus"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " deploy_cobalt_beacon" nocase ascii wide
                        $string2 = /\soctopus\.py/ nocase ascii wide
                        $string3 = /\.\/.{0,1000}octopus\.py/
                        $string4 = /\/agent\.ps1\.oct/ nocase ascii wide
                        $string5 = /\/octopus\.asm/ nocase ascii wide
                        $string6 = /\/Octopus\.git/ nocase ascii wide
                        $string7 = /\/octopusx64\.asm/ nocase ascii wide
                        $string8 = /\/weblistener\.py/ nocase ascii wide
                        $string9 = /ASBBypass\.ps1/ nocase ascii wide
                        $string10 = "generate_hta operation1" nocase ascii wide
                        $string11 = "generate_powershell operation1" nocase ascii wide
                        $string12 = "generate_spoofed_args_exe" nocase ascii wide
                        $string13 = /generate_unmanaged_exe\soperation1\s.{0,1000}\.exe/ nocase ascii wide
                        $string14 = "generate_x64_shellcode" nocase ascii wide
                        $string15 = "generate_x86_shellcode" nocase ascii wide
                        $string16 = /ILBypass\.ps1/ nocase ascii wide
                        $string17 = /listen_http\s0\.0\.0\.0\s8080\s.{0,1000}\.php\soperation1/ nocase ascii wide
                        $string18 = "mhaskar/Octopus" nocase ascii wide
                        $string19 = /octopus\.py\s/ nocase ascii wide

    condition:
        any of them
}