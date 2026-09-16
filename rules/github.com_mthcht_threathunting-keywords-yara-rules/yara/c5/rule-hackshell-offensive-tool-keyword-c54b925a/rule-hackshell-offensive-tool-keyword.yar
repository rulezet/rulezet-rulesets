rule rule_hackshell_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'hackshell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "hackshell"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_hackshell_offensive_tool_keyword = /\shackshell\.sh/ nocase ascii wide
                        $string2_hackshell_offensive_tool_keyword = /\/hackshell\.sh/ nocase ascii wide
                        $string3_hackshell_offensive_tool_keyword = /\/latest\/download\/linpeas\.sh/ nocase ascii wide
                        $string4_hackshell_offensive_tool_keyword = /\/var\/tmp\/\.socket\s\-p\s\-c\s\\"exec\spython3\s\-c\s\\\\"import\sos\;os\.setuid\(0\)\;os\.setgid\(0\)\;os\.execl/
                        $string5_hackshell_offensive_tool_keyword = "79023345917d346447982c87eae5639171d2bc091505dc0869632440bcc250f2" nocase ascii wide
                        $string6_hackshell_offensive_tool_keyword = "BASH_HISTORY=/dev/null exec -a "
                        $string7_hackshell_offensive_tool_keyword = /burl\shttp\:\/\/ipinfo\.io\s2\>\/dev\/null/ nocase ascii wide
                        $string8_hackshell_offensive_tool_keyword = /dl\shttp\:\/\/ipinfo\.io\s2\>\/dev\/nul/ nocase ascii wide
                        $string9_hackshell_offensive_tool_keyword = "echo 1 >/proc/sys/net/ipv4/conf/all/route_localnet" nocase ascii wide
                        $string10_hackshell_offensive_tool_keyword = "hackerschoice/hackshell" nocase ascii wide
                        $string11_hackshell_offensive_tool_keyword = /hackshell\-main\.zip/ nocase ascii wide
                        $string12_hackshell_offensive_tool_keyword = /http\:\/\/37\.120\.235\.188\/blah\.tar\.gz/ nocase ascii wide
                        $string13_hackshell_offensive_tool_keyword = /https\:\/\/bin\.ajam\.dev\/\/\$\(uname\s\-m\)\/bash/
                        $string14_hackshell_offensive_tool_keyword = /https\:\/\/github\.com\/hackerschoice\/thc\-tips\-tricks\-hacks\-cheat\-sheet\/raw\/master\/tools\/ghostip\.sh/ nocase ascii wide
                        $string15_hackshell_offensive_tool_keyword = /https\:\/\/github\.com\/hackerschoice\/thc\-tips\-tricks\-hacks\-cheat\-sheet\/raw\/master\/tools\/whatserver\.sh/ nocase ascii wide
                        $string16_hackshell_offensive_tool_keyword = /https\:\/\/thc\.org\/hs/ nocase ascii wide
                        $string17_hackshell_offensive_tool_keyword = /nmap\s\-Pn\s\-p.{0,1000}\s\-\-open\s\-T4\s\-n\s\-oG\s\-\s.{0,1000}\s2\>\/dev\/null\s\|\sgrep\s\-F\sPorts/ nocase ascii wide
                        $string18_hackshell_offensive_tool_keyword = /raw\.githubusercontent\.com\/peass\-ng\/PEASS\-ng\/master\/winPEAS\/winPEASps1\/winPEAS\.ps1/ nocase ascii wide
                        $string19_hackshell_offensive_tool_keyword = /source\s\<\(curl\s\-SsfL\shttps\:\/\/thc\.org\/hs\)/ nocase ascii wide
                        $string20_hackshell_offensive_tool_keyword = /SSH\-Hijack\s\(reptyr\)/ nocase ascii wide
                        $string21_hackshell_offensive_tool_keyword = /tinyurl\.com\/haxshl/ nocase ascii wide
                        $string22_hackshell_offensive_tool_keyword = "unset -f hs_init hs_init_alias hs_init_dl hs_init_shell" nocase ascii wide
                        $string23_hackshell_offensive_tool_keyword = "unset SSH_CLIENT SSH_CONNECTION; TERM=xterm-256color HISTFILE=/dev/null " nocase ascii wide

    condition:
        any of them
}