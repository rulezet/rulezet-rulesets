rule pamspy
{
    meta:
        description = "Detection patterns for the tool 'pamspy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pamspy"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sby\s\@citronneur\s\(v/
                        $string2 = /\spamspy_event\.h/
                        $string3 = "/pamspy -p "
                        $string4 = /\/pamspy\.git/
                        $string5 = /\/releases\/download\/v0\.1\/pamspy/
                        $string6 = /\/releases\/download\/v0\.2\/pamspy/
                        $string7 = /\\pamspy\.bpf\.c/
                        $string8 = /\\pamspy_event\.h/
                        $string9 = "48a7ca531d14b205dfcaaa59b86e78f3f092a2c1c6ccf8c827ee87ba30d3108c"
                        $string10 = "510898a4922120a3e1e10c935f84e2f939a022b739afb38a42cb1b5e3a00172d"
                        $string11 = "665a22568c5d38db4ce74dde13053e8a66baf91356e4f35a9e2957c205a09f1a"
                        $string12 = "9bc52d5f3a9d6d2a442de0ee8f417692b2e27993707dd5f07d17b92f9ae84684"
                        $string13 = "citronneur/pamspy"
                        $string14 = "citronneur/pamspy/releases"
                        $string15 = "pamspy: Failed to increase RLIMIT_MEMLOCK limit!"
                        $string16 = "pamspy: Failed to load BPF program: "
                        $string17 = "pamspy: Unable to find pam_get_authtok function in"
                        $string18 = /src\\pamspy\.c/
                        $string19 = /Uses\seBPF\sto\sdump\ssecrets\suse\sby\sPAM\s\(Authentication\)\smodule/

    condition:
        any of them
}