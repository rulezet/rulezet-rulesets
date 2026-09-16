rule Poshito
{
    meta:
        description = "Detection patterns for the tool 'Poshito' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Poshito"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/Poshito -w /Poshito/Poshito poshito" nocase ascii wide
                        $string2 = /\/Poshito\.dll/ nocase ascii wide
                        $string3 = /\/Poshito\.exe/ nocase ascii wide
                        $string4 = /\/Poshito\.git/ nocase ascii wide
                        $string5 = "/Poshito/Poshito/Agent"
                        $string6 = /\/PowerShdll\.exe/ nocase ascii wide
                        $string7 = /\[\+\]\sUPXed\ssuccessfully/ nocase ascii wide
                        $string8 = /\\patch_exit\.exe/ nocase ascii wide
                        $string9 = /\\Poshito\.dll/ nocase ascii wide
                        $string10 = /\\Poshito\.exe/ nocase ascii wide
                        $string11 = /\\PowerShdll\.exe/ nocase ascii wide
                        $string12 = ">PowerShdll<" nocase ascii wide
                        $string13 = "a5d8564157388d8d628ba9b8785307fd8cbbf3b6fafc1cd46160712a0015ced6" nocase ascii wide
                        $string14 = "d9fb91ea8b177ea86eefc1a62a875e55136fa268aa762fa44a377023f89b7673" nocase ascii wide
                        $string15 = "da84dfd9b5b5f068189c1a37f2f3003c402ebf6bc1080e70caa82c51ee4c2bc8" nocase ascii wide
                        $string16 = "docker build -t poshito" nocase ascii wide
                        $string17 = /go\sinstall\smvdan\.cc\/garble\@latest/ nocase ascii wide
                        $string18 = "itaymigdal/Poshito" nocase ascii wide
                        $string19 = /Password\sconfirmed\.\s\\nPoshito\sis\swelcoming\syou/ nocase ascii wide
                        $string20 = "Poshito-C2 agent builder" nocase ascii wide

    condition:
        any of them
}