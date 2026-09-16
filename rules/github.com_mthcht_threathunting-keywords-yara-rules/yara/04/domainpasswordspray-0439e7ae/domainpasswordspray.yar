rule DomainPasswordSpray
{
    meta:
        description = "Detection patterns for the tool 'DomainPasswordSpray' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DomainPasswordSpray"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\-UserList\s.{0,1000}\s\-Domain\s.{0,1000}\s\-PasswordList\s.{0,1000}\s\-OutFile\s/ nocase ascii wide
                        $string2 = /\/DomainPasswordSpray\.git/ nocase ascii wide
                        $string3 = /\\DomainPasswordSpray\\/ nocase ascii wide
                        $string4 = /\\DomainPasswordSpray\-master/ nocase ascii wide
                        $string5 = /\\sprayed\-creds\.txt/ nocase ascii wide
                        $string6 = /\\valid\-creds\.txt/ nocase ascii wide
                        $string7 = /\]\sAny\spasswords\sthat\swere\ssuccessfully\ssprayed\shave\sbeen\soutput\sto\s/ nocase ascii wide
                        $string8 = /\]\sPassword\sspraying\shas\sbegun\swith\s/ nocase ascii wide
                        $string9 = /\]\sPassword\sspraying\sis\scomplete/ nocase ascii wide
                        $string10 = "1a3c4069-8c11-4336-bef8-9a43c0ba60e2" nocase ascii wide
                        $string11 = "433d59580b95a3e3b82364729aac65643385eb4500c46eae2aab1c0567df03e6" nocase ascii wide
                        $string12 = /Cancelling\sthe\spassword\sspray\./ nocase ascii wide
                        $string13 = "dafthack/DomainPasswordSpray" nocase ascii wide
                        $string14 = "DomainPasswordSpray" nocase ascii wide
                        $string15 = /DomainPasswordSpray\.ps1/ nocase ascii wide
                        $string16 = /DomainPasswordSpray\.psm1/ nocase ascii wide
                        $string17 = /Get\-DomainUserList\s\-Domain\s.{0,1000}\s\-RemoveDisabled\s/ nocase ascii wide
                        $string18 = "Invoke-DomainPasswordSpray" nocase ascii wide
                        $string19 = "Invoke-DomainPasswordSpray" nocase ascii wide
                        $string20 = "mdavis332/DomainPasswordSpray" nocase ascii wide
                        $string21 = "PasswordSpray " nocase ascii wide

    condition:
        any of them
}