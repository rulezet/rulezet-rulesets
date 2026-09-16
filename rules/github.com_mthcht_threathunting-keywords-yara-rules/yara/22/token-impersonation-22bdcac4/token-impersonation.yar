rule Token_Impersonation
{
    meta:
        description = "Detection patterns for the tool 'Token-Impersonation' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Token-Impersonation"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " -Steal -ProcessID " nocase ascii wide
                        $string2 = /\sToken\-Impersonation\.ps1/ nocase ascii wide
                        $string3 = /\$StealToken/ nocase ascii wide
                        $string4 = /\/Token\-Impersonation\.git/ nocase ascii wide
                        $string5 = /\/Token\-Impersonation\.ps1/ nocase ascii wide
                        $string6 = /\[\+\]\sImpersonation\ssuccessful\susing\stoken\sfrom\sPID\s/ nocase ascii wide
                        $string7 = /\\Token\-Impersonation\.ps1/ nocase ascii wide
                        $string8 = "42e10ec6f9a5276060bade151ccd929325daa8ac8910ee26de5e6eebe10f77aa" nocase ascii wide
                        $string9 = "Leo4j/Token-Impersonation" nocase ascii wide
                        $string10 = "Token-Impersonation -MakeToken" nocase ascii wide
                        $string11 = "Token-Impersonation -Rev2Self" nocase ascii wide
                        $string12 = "Token-Impersonation -Steal" nocase ascii wide

    condition:
        any of them
}