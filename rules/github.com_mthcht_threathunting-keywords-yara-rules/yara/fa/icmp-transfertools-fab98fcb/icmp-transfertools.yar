rule ICMP_TransferTools
{
    meta:
        description = "Detection patterns for the tool 'ICMP-TransferTools' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ICMP-TransferTools"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /ICMP\-ReceiveFile\.py/ nocase ascii wide
                        $string2 = /ICMP\-SendFile\.py/ nocase ascii wide
                        $string3 = "Invoke-IcmpDownload" nocase ascii wide
                        $string4 = /Invoke\-IcmpDownload\.ps1/ nocase ascii wide
                        $string5 = /Invoke\-IcmpUpload\.ps1/ nocase ascii wide

    condition:
        any of them
}