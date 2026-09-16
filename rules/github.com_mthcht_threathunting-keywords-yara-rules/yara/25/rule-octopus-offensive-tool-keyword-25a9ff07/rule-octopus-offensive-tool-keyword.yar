rule rule_octopus_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'octopus' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "octopus"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_octopus_offensive_tool_keyword = " deploy_cobalt_beacon" nocase ascii wide
                        $string2_octopus_offensive_tool_keyword = /\soctopus\.py/ nocase ascii wide
                        $string3_octopus_offensive_tool_keyword = /\.\/.{0,1000}octopus\.py/
                        $string4_octopus_offensive_tool_keyword = /\/agent\.ps1\.oct/ nocase ascii wide
                        $string5_octopus_offensive_tool_keyword = /\/octopus\.asm/ nocase ascii wide
                        $string6_octopus_offensive_tool_keyword = /\/Octopus\.git/ nocase ascii wide
                        $string7_octopus_offensive_tool_keyword = /\/octopusx64\.asm/ nocase ascii wide
                        $string8_octopus_offensive_tool_keyword = /\/weblistener\.py/ nocase ascii wide
                        $string9_octopus_offensive_tool_keyword = /ASBBypass\.ps1/ nocase ascii wide
                        $string10_octopus_offensive_tool_keyword = "generate_hta operation1" nocase ascii wide
                        $string11_octopus_offensive_tool_keyword = "generate_powershell operation1" nocase ascii wide
                        $string12_octopus_offensive_tool_keyword = "generate_spoofed_args_exe" nocase ascii wide
                        $string13_octopus_offensive_tool_keyword = /generate_unmanaged_exe\soperation1\s.{0,1000}\.exe/ nocase ascii wide
                        $string14_octopus_offensive_tool_keyword = "generate_x64_shellcode" nocase ascii wide
                        $string15_octopus_offensive_tool_keyword = "generate_x86_shellcode" nocase ascii wide
                        $string16_octopus_offensive_tool_keyword = /ILBypass\.ps1/ nocase ascii wide
                        $string17_octopus_offensive_tool_keyword = /listen_http\s0\.0\.0\.0\s8080\s.{0,1000}\.php\soperation1/ nocase ascii wide
                        $string18_octopus_offensive_tool_keyword = "mhaskar/Octopus" nocase ascii wide
                        $string19_octopus_offensive_tool_keyword = /octopus\.py\s/ nocase ascii wide

    condition:
        any of them
}