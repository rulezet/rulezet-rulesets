rule NtlmRelayToEWS
{
    meta:
        description = "Detection patterns for the tool 'NtlmRelayToEWS' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NtlmRelayToEWS"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\shttprelayserver\.py/ nocase ascii wide
                        $string2 = /\ssmbrelayserver\.py/ nocase ascii wide
                        $string3 = /\/httprelayserver\.py/ nocase ascii wide
                        $string4 = /\/NtlmRelayToEWS\.git/ nocase ascii wide
                        $string5 = "/NtlmRelayToEWS/" nocase ascii wide
                        $string6 = /\/smbrelayserver\.py/ nocase ascii wide
                        $string7 = /\\httprelayserver\.py/ nocase ascii wide
                        $string8 = /\\NtlmRelayToEWS\\/ nocase ascii wide
                        $string9 = /\\smbrelayserver\.py/ nocase ascii wide
                        $string10 = "Arno0x/NtlmRelayToEWS" nocase ascii wide
                        $string11 = "ntlmRelayToEWS -" nocase ascii wide
                        $string12 = /ntlmRelayToEWS\.py/ nocase ascii wide
                        $string13 = "NtlmRelayToEWS-master" nocase ascii wide

    condition:
        any of them
}