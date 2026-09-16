rule rule_pamspy_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'pamspy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pamspy"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_pamspy_offensive_tool_keyword = /\sby\s\@citronneur\s\(v/
                        $string2_pamspy_offensive_tool_keyword = /\spamspy_event\.h/
                        $string3_pamspy_offensive_tool_keyword = "/pamspy -p "
                        $string4_pamspy_offensive_tool_keyword = /\/pamspy\.git/
                        $string5_pamspy_offensive_tool_keyword = /\/releases\/download\/v0\.1\/pamspy/
                        $string6_pamspy_offensive_tool_keyword = /\/releases\/download\/v0\.2\/pamspy/
                        $string7_pamspy_offensive_tool_keyword = /\\pamspy\.bpf\.c/
                        $string8_pamspy_offensive_tool_keyword = /\\pamspy_event\.h/
                        $string9_pamspy_offensive_tool_keyword = "48a7ca531d14b205dfcaaa59b86e78f3f092a2c1c6ccf8c827ee87ba30d3108c"
                        $string10_pamspy_offensive_tool_keyword = "510898a4922120a3e1e10c935f84e2f939a022b739afb38a42cb1b5e3a00172d"
                        $string11_pamspy_offensive_tool_keyword = "665a22568c5d38db4ce74dde13053e8a66baf91356e4f35a9e2957c205a09f1a"
                        $string12_pamspy_offensive_tool_keyword = "9bc52d5f3a9d6d2a442de0ee8f417692b2e27993707dd5f07d17b92f9ae84684"
                        $string13_pamspy_offensive_tool_keyword = "citronneur/pamspy"
                        $string14_pamspy_offensive_tool_keyword = "citronneur/pamspy/releases"
                        $string15_pamspy_offensive_tool_keyword = "pamspy: Failed to increase RLIMIT_MEMLOCK limit!"
                        $string16_pamspy_offensive_tool_keyword = "pamspy: Failed to load BPF program: "
                        $string17_pamspy_offensive_tool_keyword = "pamspy: Unable to find pam_get_authtok function in"
                        $string18_pamspy_offensive_tool_keyword = /src\\pamspy\.c/
                        $string19_pamspy_offensive_tool_keyword = /Uses\seBPF\sto\sdump\ssecrets\suse\sby\sPAM\s\(Authentication\)\smodule/

    condition:
        any of them
}