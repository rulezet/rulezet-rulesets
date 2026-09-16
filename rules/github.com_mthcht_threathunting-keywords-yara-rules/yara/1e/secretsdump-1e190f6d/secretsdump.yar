rule secretsdump
{
    meta:
        description = "Detection patterns for the tool 'secretsdump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "secretsdump"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " -just-dc-ntlm " nocase ascii wide
                        $string2 = " -just-dc-user " nocase ascii wide
                        $string3 = /\/cached\-domain\-credentials\.html/ nocase ascii wide
                        $string4 = /\/decrypting\-lsa\-secrets\.html/ nocase ascii wide
                        $string5 = /\/syskey\-and\-sam\.html/ nocase ascii wide
                        $string6 = /\]\sDumping\ssecrets\sfor\:\s.{0,1000}Username\:\s/ nocase ascii wide
                        $string7 = "29cf4b68c34663281bebc94f62c92282ca351839032140fcb2b0266d44a8bc84" nocase ascii wide
                        $string8 = "fin3ss3g0d/secretsdump" nocase ascii wide
                        $string9 = /impacket\.examples\.secretsdump/ nocase ascii wide
                        $string10 = "Policy SPN target name validation might be restricting full DRSUAPI dump" nocase ascii wide
                        $string11 = /resuming\sa\sprevious\sNTDS\.DIT\sdump\ssession/ nocase ascii wide
                        $string12 = /secretsdump\.py/ nocase ascii wide

    condition:
        any of them
}