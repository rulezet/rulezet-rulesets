rule hackshell
{
    meta:
        description = "Detection patterns for the tool 'hackshell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "hackshell"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\shackshell\.sh/ nocase ascii wide
                        $string2 = /\/hackshell\.sh/ nocase ascii wide
                        $string3 = /\/latest\/download\/linpeas\.sh/ nocase ascii wide
                        $string4 = /\/var\/tmp\/\.socket\s\-p\s\-c\s\\"exec\spython3\s\-c\s\\\\"import\sos\;os\.setuid\(0\)\;os\.setgid\(0\)\;os\.execl/
                        $string5 = "79023345917d346447982c87eae5639171d2bc091505dc0869632440bcc250f2" nocase ascii wide
                        $string6 = "BASH_HISTORY=/dev/null exec -a "
                        $string7 = /burl\shttp\:\/\/ipinfo\.io\s2\>\/dev\/null/ nocase ascii wide
                        $string8 = /dl\shttp\:\/\/ipinfo\.io\s2\>\/dev\/nul/ nocase ascii wide
                        $string9 = "echo 1 >/proc/sys/net/ipv4/conf/all/route_localnet" nocase ascii wide
                        $string10 = "hackerschoice/hackshell" nocase ascii wide
                        $string11 = /hackshell\-main\.zip/ nocase ascii wide
                        $string12 = /http\:\/\/37\.120\.235\.188\/blah\.tar\.gz/ nocase ascii wide
                        $string13 = /https\:\/\/bin\.ajam\.dev\/\/\$\(uname\s\-m\)\/bash/
                        $string14 = /https\:\/\/github\.com\/hackerschoice\/thc\-tips\-tricks\-hacks\-cheat\-sheet\/raw\/master\/tools\/ghostip\.sh/ nocase ascii wide
                        $string15 = /https\:\/\/github\.com\/hackerschoice\/thc\-tips\-tricks\-hacks\-cheat\-sheet\/raw\/master\/tools\/whatserver\.sh/ nocase ascii wide
                        $string16 = /https\:\/\/thc\.org\/hs/ nocase ascii wide
                        $string17 = /nmap\s\-Pn\s\-p.{0,100}\s\-\-open\s\-T4\s\-n\s\-oG\s\-\s.{0,100}\s2\>\/dev\/null\s\|\sgrep\s\-F\sPorts/ nocase ascii wide
                        $string18 = /raw\.githubusercontent\.com\/peass\-ng\/PEASS\-ng\/master\/winPEAS\/winPEASps1\/winPEAS\.ps1/ nocase ascii wide
                        $string19 = /source\s\<\(curl\s\-SsfL\shttps\:\/\/thc\.org\/hs\)/ nocase ascii wide
                        $string20 = /SSH\-Hijack\s\(reptyr\)/ nocase ascii wide
                        $string21 = /tinyurl\.com\/haxshl/ nocase ascii wide
                        $string22 = "unset -f hs_init hs_init_alias hs_init_dl hs_init_shell" nocase ascii wide
                        $string23 = "unset SSH_CLIENT SSH_CONNECTION; TERM=xterm-256color HISTFILE=/dev/null " nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or             uint16(0) == 0x457f or             uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or             uint32(0) == 0x504B0304 or             uint32(0) == 0xCAFEBABE or             uint32(0) == 0x4D534346 or             uint32(0) == 0xD0CF11E0 or             uint16(0) == 0x2321 or             uint16(0) == 0x3c3f         )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}