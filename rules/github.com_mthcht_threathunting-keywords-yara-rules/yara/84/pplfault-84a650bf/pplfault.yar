rule PPLFault
{
    meta:
        description = "Detection patterns for the tool 'PPLFault' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PPLFault"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/DumpShellcode/" nocase ascii wide
                        $string2 = /\/Nofault\.exe/ nocase ascii wide
                        $string3 = "/PPLFault/" nocase ascii wide
                        $string4 = /\\GodFault\./ nocase ascii wide
                        $string5 = /\\Nofault\.exe/ nocase ascii wide
                        $string6 = /\\PPLFault/ nocase ascii wide
                        $string7 = /DumpShellcode\./ nocase ascii wide
                        $string8 = /DumpShellcode\\/ nocase ascii wide
                        $string9 = /EventAggregation\.dll\.bak/ nocase ascii wide
                        $string10 = /EventAggregation\.dll\.patched/ nocase ascii wide
                        $string11 = /EventAggregationPH\.dll/ nocase ascii wide
                        $string12 = "gabriellandau/PPLFault" nocase ascii wide
                        $string13 = "GMShellcode" nocase ascii wide
                        $string14 = /GMShellcode\./ nocase ascii wide
                        $string15 = /GMShellcode\\/ nocase ascii wide
                        $string16 = /GodFault\.exe/ nocase ascii wide
                        $string17 = /GodFault\\GodFault/ nocase ascii wide
                        $string18 = "HIJACK_DLL_PATH" nocase ascii wide
                        $string19 = /lsass\.dmp/ nocase ascii wide
                        $string20 = /NoFault\\NoFault\./ nocase ascii wide
                        $string21 = /PPLFault\./ nocase ascii wide
                        $string22 = /PPLFault\.exe/ nocase ascii wide
                        $string23 = /PPLFault\-Localhost\-SMB\.ps1/ nocase ascii wide
                        $string24 = /PPLFaultPayload\.dll/ nocase ascii wide
                        $string25 = "PPLFaultTemp" nocase ascii wide
                        $string26 = /smbserver\.py\s\-payload/ nocase ascii wide

    condition:
        any of them
}