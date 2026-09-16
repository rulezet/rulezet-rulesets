rule rule_bpf_keylogger_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'bpf-keylogger' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "bpf-keylogger"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_bpf_keylogger_offensive_tool_keyword = /\(prog\=\\"bpf\-keylogger\\"/ nocase ascii wide
                        $string2_bpf_keylogger_offensive_tool_keyword = /\/bpf\-keylogger\.git/ nocase ascii wide
                        $string3_bpf_keylogger_offensive_tool_keyword = "/bpf-keylogger/" nocase ascii wide
                        $string4_bpf_keylogger_offensive_tool_keyword = /A\skeylogger\swritten\sin\seBPF\./ nocase ascii wide
                        $string5_bpf_keylogger_offensive_tool_keyword = "bpf_keylogger: Log key presses and mouse button events systemwide using eBPF" nocase ascii wide
                        $string6_bpf_keylogger_offensive_tool_keyword = /Logging\skey\spresses\.\.\.\sctrl\-c\sto\squit/ nocase ascii wide
                        $string7_bpf_keylogger_offensive_tool_keyword = "SkyperTHC/bpf-keylogger" nocase ascii wide
                        $string8_bpf_keylogger_offensive_tool_keyword = "willfindlay/bpf-keylogger" nocase ascii wide

    condition:
        any of them
}