rule rule_DomainPasswordSpray_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'DomainPasswordSpray' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DomainPasswordSpray"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_DomainPasswordSpray_offensive_tool_keyword = /\s\-UserList\s.{0,1000}\s\-Domain\s.{0,1000}\s\-PasswordList\s.{0,1000}\s\-OutFile\s/ nocase ascii wide
                        $string2_DomainPasswordSpray_offensive_tool_keyword = /\/DomainPasswordSpray\.git/ nocase ascii wide
                        $string3_DomainPasswordSpray_offensive_tool_keyword = /\\DomainPasswordSpray\\/ nocase ascii wide
                        $string4_DomainPasswordSpray_offensive_tool_keyword = /\\DomainPasswordSpray\-master/ nocase ascii wide
                        $string5_DomainPasswordSpray_offensive_tool_keyword = /\\sprayed\-creds\.txt/ nocase ascii wide
                        $string6_DomainPasswordSpray_offensive_tool_keyword = /\\valid\-creds\.txt/ nocase ascii wide
                        $string7_DomainPasswordSpray_offensive_tool_keyword = /\]\sAny\spasswords\sthat\swere\ssuccessfully\ssprayed\shave\sbeen\soutput\sto\s/ nocase ascii wide
                        $string8_DomainPasswordSpray_offensive_tool_keyword = /\]\sPassword\sspraying\shas\sbegun\swith\s/ nocase ascii wide
                        $string9_DomainPasswordSpray_offensive_tool_keyword = /\]\sPassword\sspraying\sis\scomplete/ nocase ascii wide
                        $string10_DomainPasswordSpray_offensive_tool_keyword = "1a3c4069-8c11-4336-bef8-9a43c0ba60e2" nocase ascii wide
                        $string11_DomainPasswordSpray_offensive_tool_keyword = "433d59580b95a3e3b82364729aac65643385eb4500c46eae2aab1c0567df03e6" nocase ascii wide
                        $string12_DomainPasswordSpray_offensive_tool_keyword = /Cancelling\sthe\spassword\sspray\./ nocase ascii wide
                        $string13_DomainPasswordSpray_offensive_tool_keyword = "dafthack/DomainPasswordSpray" nocase ascii wide
                        $string14_DomainPasswordSpray_offensive_tool_keyword = "DomainPasswordSpray" nocase ascii wide
                        $string15_DomainPasswordSpray_offensive_tool_keyword = /DomainPasswordSpray\.ps1/ nocase ascii wide
                        $string16_DomainPasswordSpray_offensive_tool_keyword = /DomainPasswordSpray\.psm1/ nocase ascii wide
                        $string17_DomainPasswordSpray_offensive_tool_keyword = /Get\-DomainUserList\s\-Domain\s.{0,1000}\s\-RemoveDisabled\s/ nocase ascii wide
                        $string18_DomainPasswordSpray_offensive_tool_keyword = "Invoke-DomainPasswordSpray" nocase ascii wide
                        $string19_DomainPasswordSpray_offensive_tool_keyword = "Invoke-DomainPasswordSpray" nocase ascii wide
                        $string20_DomainPasswordSpray_offensive_tool_keyword = "mdavis332/DomainPasswordSpray" nocase ascii wide
                        $string21_DomainPasswordSpray_offensive_tool_keyword = "PasswordSpray " nocase ascii wide

    condition:
        any of them
}