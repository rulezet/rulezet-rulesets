rule REC2_
{
    meta:
        description = "Detection patterns for the tool 'REC2 ' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "REC2 "
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/REC2\.git/ nocase ascii wide
                        $string2 = /\\REC2\-main\.zip/ nocase ascii wide
                        $string3 = "a78983b009b688a82458abac952516db57dc7eb3118a35cc737dde29c7b87ec4" nocase ascii wide
                        $string4 = "c2server_arm_musl" nocase ascii wide
                        $string5 = "c2server_armv7" nocase ascii wide
                        $string6 = "c2server_debug" nocase ascii wide
                        $string7 = "c2server_linux"
                        $string8 = "c2server_macos" nocase ascii wide
                        $string9 = "c2server_release" nocase ascii wide
                        $string10 = "c2server_windows" nocase ascii wide
                        $string11 = /crate\:\:modules\:\:\{rec2mastodon.{0,1000}rec2virustotal\}/ nocase ascii wide
                        $string12 = "d09ccee4-pass-word-0000-98677e2356fd" nocase ascii wide
                        $string13 = "g0h4n/REC2" nocase ascii wide
                        $string14 = /https\:\/\/mastodon\.be\/\@username_fzihfzuhfuoz\/109994357971853428/ nocase ascii wide
                        $string15 = /https\:\/\/mastodon\.be\/username_fzihfzuhfuoz\/109743339821428173/ nocase ascii wide
                        $string16 = "RAMDOMdd28f0dcd9779315ee130deb565dbf315587f1611e54PASSWORD" nocase ascii wide
                        $string17 = "REC2 implant for Mastodon" nocase ascii wide
                        $string18 = "REC2 implant for VirusTotal" nocase ascii wide
                        $string19 = "rec2::modules::rec2mastodon" nocase ascii wide
                        $string20 = /rec2_mastodon_x64\.exe/ nocase ascii wide
                        $string21 = /rec2_virustotal_x64\.exe/ nocase ascii wide
                        $string22 = /rec2mastodon\.rs/ nocase ascii wide
                        $string23 = "rec2virustotal" nocase ascii wide
                        $string24 = /rec2virustotal\.rs/ nocase ascii wide
                        $string25 = "TMVB6XJWzuz4KsqUCnwxrtooQV9LmP6R4IX62HeQ7OZzhxgsahsxNzf05dJNkntl" nocase ascii wide
                        $string26 = "Using VirusToal website as external C2" nocase ascii wide
                        $string27 = "WkIKjtCbQzcqQd04ZsE4sFefvpjryhU5w9iVFxGz1oU" nocase ascii wide

    condition:
        any of them
}