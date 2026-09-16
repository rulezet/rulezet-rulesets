rule rule_BetterSafetyKatz_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'BetterSafetyKatz' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BetterSafetyKatz"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_BetterSafetyKatz_offensive_tool_keyword = "aHR0cDovL3BpbmdjYXN0bGUuY29t" nocase ascii wide
                        $string2_BetterSafetyKatz_offensive_tool_keyword = /BetterSafetyKatz\.exe/ nocase ascii wide
                        $string3_BetterSafetyKatz_offensive_tool_keyword = "bG9nb25QYXNzd29yZHM=" nocase ascii wide
                        $string4_BetterSafetyKatz_offensive_tool_keyword = "bWltaWthdHo=" nocase ascii wide
                        $string5_BetterSafetyKatz_offensive_tool_keyword = "dmluY2VudC5sZXRvdXhAZ21haWwuY29t" nocase ascii wide
                        $string6_BetterSafetyKatz_offensive_tool_keyword = "eDY0L21pbWlrYXR6LmV4ZQ==" nocase ascii wide
                        $string7_BetterSafetyKatz_offensive_tool_keyword = "L3NhbSBvciAvc2lkIHRvIHRhcmdldCB0aGUgYWNjb3VudCBpcyBuZWVkZWQ=" nocase ascii wide
                        $string8_BetterSafetyKatz_offensive_tool_keyword = "Process is not 64-bit, this version of katz won't work yo'!" nocase ascii wide
                        $string9_BetterSafetyKatz_offensive_tool_keyword = "QmVuamFtaW4gREVMUFk=" nocase ascii wide
                        $string10_BetterSafetyKatz_offensive_tool_keyword = "QSBMYSBWaWUsIEEgTCdBbW91cg==" nocase ascii wide
                        $string11_BetterSafetyKatz_offensive_tool_keyword = "RHVtcENyZWRz" nocase ascii wide
                        $string12_BetterSafetyKatz_offensive_tool_keyword = "S2l3aUFuZENNRA==" nocase ascii wide
                        $string13_BetterSafetyKatz_offensive_tool_keyword = "TGlzdHMgYWxsIGF2YWlsYWJsZSBwcm92aWRlcnMgY3JlZGVudGlhbHM=" nocase ascii wide
                        $string14_BetterSafetyKatz_offensive_tool_keyword = "U3dpdGNoIChvciByZWluaXQpIHRvIExTQVNTIHByb2Nlc3MgIGNvbnRleHQ=" nocase ascii wide
                        $string15_BetterSafetyKatz_offensive_tool_keyword = "W2V4cGVyaW1lbnRhbF0gcGF0Y2ggVGVybWluYWwgU2VydmVyIHNlcnZpY2UgdG8gYWxsb3cgbXVsdGlwbGVzIHVzZXJz" nocase ascii wide
                        $string16_BetterSafetyKatz_offensive_tool_keyword = "Z2VudGlsa2l3aQ==" nocase ascii wide

    condition:
        any of them
}