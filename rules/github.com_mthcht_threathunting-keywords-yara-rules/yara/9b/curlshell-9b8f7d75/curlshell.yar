rule curlshell
{
    meta:
        description = "Detection patterns for the tool 'curlshell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "curlshell"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\scurlshell\.py/
                        $string2 = /\.py\s.{0,1000}0\.0\.0\.0.{0,1000}\-\-serve\-forever/
                        $string3 = /\.py\s.{0,1000}\-\-dependabot\-workaround/
                        $string4 = /\.py\s\-\-certificate\s.{0,1000}\.pem\s\-\-private\-key\s.{0,1000}\.pem\s\-\-listen\-port\s/
                        $string5 = /\.py\s\-\-certificate\sfullchain\.pem\s\-\-private\-key\sprivkey\.pem\s\-\-listen\-port\s/
                        $string6 = /\/curlshell\.git/ nocase ascii wide
                        $string7 = /\/curlshell\.git/ nocase ascii wide
                        $string8 = /\/curlshell\.py/ nocase ascii wide
                        $string9 = /\/curlshell\-main\./ nocase ascii wide
                        $string10 = "/curlshell-main/" nocase ascii wide
                        $string11 = /\\curlshell\.py/ nocase ascii wide
                        $string12 = /\\curlshell\-main/ nocase ascii wide
                        $string13 = /\\curlshell\-main\\/ nocase ascii wide
                        $string14 = "b8285e421d702738eab45670ecae439a7228994e7068b04cb51740e47efbfb41" nocase ascii wide
                        $string15 = "curl https://curlshell"
                        $string16 = /curlshell\.py/
                        $string17 = "https://curlshell:"
                        $string18 = /https\:\/\/curlshell\:.{0,1000}\s\|\sbash/
                        $string19 = "irsl/curlshell"

    condition:
        any of them
}