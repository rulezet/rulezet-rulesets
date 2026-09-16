rule rule_ICMP_TransferTools_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ICMP-TransferTools' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ICMP-TransferTools"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ICMP_TransferTools_offensive_tool_keyword = /ICMP\-ReceiveFile\.py/ nocase ascii wide
                        $string2_ICMP_TransferTools_offensive_tool_keyword = /ICMP\-SendFile\.py/ nocase ascii wide
                        $string3_ICMP_TransferTools_offensive_tool_keyword = "Invoke-IcmpDownload" nocase ascii wide
                        $string4_ICMP_TransferTools_offensive_tool_keyword = /Invoke\-IcmpDownload\.ps1/ nocase ascii wide
                        $string5_ICMP_TransferTools_offensive_tool_keyword = /Invoke\-IcmpUpload\.ps1/ nocase ascii wide

    condition:
        any of them
}