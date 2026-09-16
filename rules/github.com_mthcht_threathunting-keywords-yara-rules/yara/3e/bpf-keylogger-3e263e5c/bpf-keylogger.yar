rule bpf_keylogger
{
    meta:
        description = "Detection patterns for the tool 'bpf-keylogger' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "bpf-keylogger"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\(prog\=\\"bpf\-keylogger\\"/ nocase ascii wide
                        $string2 = /\/bpf\-keylogger\.git/ nocase ascii wide
                        $string3 = "/bpf-keylogger/" nocase ascii wide
                        $string4 = /A\skeylogger\swritten\sin\seBPF\./ nocase ascii wide
                        $string5 = "bpf_keylogger: Log key presses and mouse button events systemwide using eBPF" nocase ascii wide
                        $string6 = /Logging\skey\spresses\.\.\.\sctrl\-c\sto\squit/ nocase ascii wide
                        $string7 = "SkyperTHC/bpf-keylogger" nocase ascii wide
                        $string8 = "willfindlay/bpf-keylogger" nocase ascii wide

    condition:
        any of them
}