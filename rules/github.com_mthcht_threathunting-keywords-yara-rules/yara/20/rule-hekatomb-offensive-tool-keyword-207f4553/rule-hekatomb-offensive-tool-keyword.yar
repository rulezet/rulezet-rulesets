rule rule_HEKATOMB_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'HEKATOMB' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "HEKATOMB"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_HEKATOMB_offensive_tool_keyword = " install hekatomb" nocase ascii wide
                        $string2_HEKATOMB_offensive_tool_keyword = /\.py\s.{0,1000}\s\-debug\s\-dnstcp/ nocase ascii wide
                        $string3_HEKATOMB_offensive_tool_keyword = /\/exported_credentials\.csv/
                        $string4_HEKATOMB_offensive_tool_keyword = /\[\+\]\sConnnecting\sto\sall\scomputers\sand\stry\sto\sget\sdpapi\sblobs\sand\smaster\skey\sfiles/ nocase ascii wide
                        $string5_HEKATOMB_offensive_tool_keyword = /\[\+\]\sScanning\scomputers\slist\son\sSMB\sport\s/ nocase ascii wide
                        $string6_HEKATOMB_offensive_tool_keyword = /\\exported_credentials\.csv/ nocase ascii wide
                        $string7_HEKATOMB_offensive_tool_keyword = "ed9d3ee993fe0a36bb7a7fce3940112ea29eccca58165738a758c58a3fe0ae54" nocase ascii wide
                        $string8_HEKATOMB_offensive_tool_keyword = "hekatomb -hashes " nocase ascii wide
                        $string9_HEKATOMB_offensive_tool_keyword = /hekatomb\-.{0,1000}\.tar\.gz/ nocase ascii wide
                        $string10_HEKATOMB_offensive_tool_keyword = /hekatomb.{0,1000}\-hashes\s/ nocase ascii wide
                        $string11_HEKATOMB_offensive_tool_keyword = /hekatomb\-.{0,1000}\-py3\-none\-any\.whl/ nocase ascii wide
                        $string12_HEKATOMB_offensive_tool_keyword = /hekatomb\.ad_ldap/ nocase ascii wide
                        $string13_HEKATOMB_offensive_tool_keyword = /hekatomb\@thiefin\.fr/ nocase ascii wide
                        $string14_HEKATOMB_offensive_tool_keyword = "it will extract domain controller private key through RPC uses it to decrypt all credentials" nocase ascii wide
                        $string15_HEKATOMB_offensive_tool_keyword = /New\scredentials\sfound\sfor\suser\s.{0,1000}\son\s/ nocase ascii wide
                        $string16_HEKATOMB_offensive_tool_keyword = "pacman -S hekatomb" nocase ascii wide
                        $string17_HEKATOMB_offensive_tool_keyword = "poetry run hekatomb" nocase ascii wide
                        $string18_HEKATOMB_offensive_tool_keyword = "Processus-Thief/HEKATOMB" nocase ascii wide

    condition:
        any of them
}