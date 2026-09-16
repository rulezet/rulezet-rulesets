rule rule_PPLFault_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'PPLFault' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PPLFault"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_PPLFault_offensive_tool_keyword = "/DumpShellcode/" nocase ascii wide
                        $string2_PPLFault_offensive_tool_keyword = /\/Nofault\.exe/ nocase ascii wide
                        $string3_PPLFault_offensive_tool_keyword = "/PPLFault/" nocase ascii wide
                        $string4_PPLFault_offensive_tool_keyword = /\\GodFault\./ nocase ascii wide
                        $string5_PPLFault_offensive_tool_keyword = /\\Nofault\.exe/ nocase ascii wide
                        $string6_PPLFault_offensive_tool_keyword = /\\PPLFault/ nocase ascii wide
                        $string7_PPLFault_offensive_tool_keyword = /DumpShellcode\./ nocase ascii wide
                        $string8_PPLFault_offensive_tool_keyword = /DumpShellcode\\/ nocase ascii wide
                        $string9_PPLFault_offensive_tool_keyword = /EventAggregation\.dll\.bak/ nocase ascii wide
                        $string10_PPLFault_offensive_tool_keyword = /EventAggregation\.dll\.patched/ nocase ascii wide
                        $string11_PPLFault_offensive_tool_keyword = /EventAggregationPH\.dll/ nocase ascii wide
                        $string12_PPLFault_offensive_tool_keyword = "gabriellandau/PPLFault" nocase ascii wide
                        $string13_PPLFault_offensive_tool_keyword = "GMShellcode" nocase ascii wide
                        $string14_PPLFault_offensive_tool_keyword = /GMShellcode\./ nocase ascii wide
                        $string15_PPLFault_offensive_tool_keyword = /GMShellcode\\/ nocase ascii wide
                        $string16_PPLFault_offensive_tool_keyword = /GodFault\.exe/ nocase ascii wide
                        $string17_PPLFault_offensive_tool_keyword = /GodFault\\GodFault/ nocase ascii wide
                        $string18_PPLFault_offensive_tool_keyword = "HIJACK_DLL_PATH" nocase ascii wide
                        $string19_PPLFault_offensive_tool_keyword = /lsass\.dmp/ nocase ascii wide
                        $string20_PPLFault_offensive_tool_keyword = /NoFault\\NoFault\./ nocase ascii wide
                        $string21_PPLFault_offensive_tool_keyword = /PPLFault\./ nocase ascii wide
                        $string22_PPLFault_offensive_tool_keyword = /PPLFault\.exe/ nocase ascii wide
                        $string23_PPLFault_offensive_tool_keyword = /PPLFault\-Localhost\-SMB\.ps1/ nocase ascii wide
                        $string24_PPLFault_offensive_tool_keyword = /PPLFaultPayload\.dll/ nocase ascii wide
                        $string25_PPLFault_offensive_tool_keyword = "PPLFaultTemp" nocase ascii wide
                        $string26_PPLFault_offensive_tool_keyword = /smbserver\.py\s\-payload/ nocase ascii wide

    condition:
        any of them
}