rule rule_NtlmRelayToEWS_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'NtlmRelayToEWS' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NtlmRelayToEWS"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_NtlmRelayToEWS_offensive_tool_keyword = /\shttprelayserver\.py/ nocase ascii wide
                        $string2_NtlmRelayToEWS_offensive_tool_keyword = /\ssmbrelayserver\.py/ nocase ascii wide
                        $string3_NtlmRelayToEWS_offensive_tool_keyword = /\/httprelayserver\.py/ nocase ascii wide
                        $string4_NtlmRelayToEWS_offensive_tool_keyword = /\/NtlmRelayToEWS\.git/ nocase ascii wide
                        $string5_NtlmRelayToEWS_offensive_tool_keyword = "/NtlmRelayToEWS/" nocase ascii wide
                        $string6_NtlmRelayToEWS_offensive_tool_keyword = /\/smbrelayserver\.py/ nocase ascii wide
                        $string7_NtlmRelayToEWS_offensive_tool_keyword = /\\httprelayserver\.py/ nocase ascii wide
                        $string8_NtlmRelayToEWS_offensive_tool_keyword = /\\NtlmRelayToEWS\\/ nocase ascii wide
                        $string9_NtlmRelayToEWS_offensive_tool_keyword = /\\smbrelayserver\.py/ nocase ascii wide
                        $string10_NtlmRelayToEWS_offensive_tool_keyword = "Arno0x/NtlmRelayToEWS" nocase ascii wide
                        $string11_NtlmRelayToEWS_offensive_tool_keyword = "ntlmRelayToEWS -" nocase ascii wide
                        $string12_NtlmRelayToEWS_offensive_tool_keyword = /ntlmRelayToEWS\.py/ nocase ascii wide
                        $string13_NtlmRelayToEWS_offensive_tool_keyword = "NtlmRelayToEWS-master" nocase ascii wide

    condition:
        any of them
}