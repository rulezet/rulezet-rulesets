rule BetterSafetyKatz
{
    meta:
        description = "Detection patterns for the tool 'BetterSafetyKatz' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BetterSafetyKatz"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "aHR0cDovL3BpbmdjYXN0bGUuY29t" nocase ascii wide
                        $string2 = /BetterSafetyKatz\.exe/ nocase ascii wide
                        $string3 = "bG9nb25QYXNzd29yZHM=" nocase ascii wide
                        $string4 = "bWltaWthdHo=" nocase ascii wide
                        $string5 = "dmluY2VudC5sZXRvdXhAZ21haWwuY29t" nocase ascii wide
                        $string6 = "eDY0L21pbWlrYXR6LmV4ZQ==" nocase ascii wide
                        $string7 = "L3NhbSBvciAvc2lkIHRvIHRhcmdldCB0aGUgYWNjb3VudCBpcyBuZWVkZWQ=" nocase ascii wide
                        $string8 = "Process is not 64-bit, this version of katz won't work yo'!" nocase ascii wide
                        $string9 = "QmVuamFtaW4gREVMUFk=" nocase ascii wide
                        $string10 = "QSBMYSBWaWUsIEEgTCdBbW91cg==" nocase ascii wide
                        $string11 = "RHVtcENyZWRz" nocase ascii wide
                        $string12 = "S2l3aUFuZENNRA==" nocase ascii wide
                        $string13 = "TGlzdHMgYWxsIGF2YWlsYWJsZSBwcm92aWRlcnMgY3JlZGVudGlhbHM=" nocase ascii wide
                        $string14 = "U3dpdGNoIChvciByZWluaXQpIHRvIExTQVNTIHByb2Nlc3MgIGNvbnRleHQ=" nocase ascii wide
                        $string15 = "W2V4cGVyaW1lbnRhbF0gcGF0Y2ggVGVybWluYWwgU2VydmVyIHNlcnZpY2UgdG8gYWxsb3cgbXVsdGlwbGVzIHVzZXJz" nocase ascii wide
                        $string16 = "Z2VudGlsa2l3aQ==" nocase ascii wide

    condition:
        any of them
}