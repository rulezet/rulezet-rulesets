rule HEKATOMB
{
    meta:
        description = "Detection patterns for the tool 'HEKATOMB' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "HEKATOMB"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " install hekatomb" nocase ascii wide
                        $string2 = /\.py\s.{0,1000}\s\-debug\s\-dnstcp/ nocase ascii wide
                        $string3 = /\/exported_credentials\.csv/
                        $string4 = /\[\+\]\sConnnecting\sto\sall\scomputers\sand\stry\sto\sget\sdpapi\sblobs\sand\smaster\skey\sfiles/ nocase ascii wide
                        $string5 = /\[\+\]\sScanning\scomputers\slist\son\sSMB\sport\s/ nocase ascii wide
                        $string6 = /\\exported_credentials\.csv/ nocase ascii wide
                        $string7 = "ed9d3ee993fe0a36bb7a7fce3940112ea29eccca58165738a758c58a3fe0ae54" nocase ascii wide
                        $string8 = "hekatomb -hashes " nocase ascii wide
                        $string9 = /hekatomb\-.{0,1000}\.tar\.gz/ nocase ascii wide
                        $string10 = /hekatomb.{0,1000}\-hashes\s/ nocase ascii wide
                        $string11 = /hekatomb\-.{0,1000}\-py3\-none\-any\.whl/ nocase ascii wide
                        $string12 = /hekatomb\.ad_ldap/ nocase ascii wide
                        $string13 = /hekatomb\@thiefin\.fr/ nocase ascii wide
                        $string14 = "it will extract domain controller private key through RPC uses it to decrypt all credentials" nocase ascii wide
                        $string15 = /New\scredentials\sfound\sfor\suser\s.{0,1000}\son\s/ nocase ascii wide
                        $string16 = "pacman -S hekatomb" nocase ascii wide
                        $string17 = "poetry run hekatomb" nocase ascii wide
                        $string18 = "Processus-Thief/HEKATOMB" nocase ascii wide

    condition:
        any of them
}