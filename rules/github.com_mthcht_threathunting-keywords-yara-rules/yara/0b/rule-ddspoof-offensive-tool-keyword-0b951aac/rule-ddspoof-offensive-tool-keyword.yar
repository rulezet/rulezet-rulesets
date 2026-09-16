rule rule_DDSpoof_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'DDSpoof' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DDSpoof"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_DDSpoof_offensive_tool_keyword = /\sddspoof\.py/ nocase ascii wide
                        $string2_DDSpoof_offensive_tool_keyword = /\sdhcp_dns_update_utils\.py/ nocase ascii wide
                        $string3_DDSpoof_offensive_tool_keyword = /\/DDSpoof\.git/ nocase ascii wide
                        $string4_DDSpoof_offensive_tool_keyword = /\/ddspoof\.py/ nocase ascii wide
                        $string5_DDSpoof_offensive_tool_keyword = /\\ddspoof\.py/ nocase ascii wide
                        $string6_DDSpoof_offensive_tool_keyword = /\\DDSpoof\\networking\\/ nocase ascii wide
                        $string7_DDSpoof_offensive_tool_keyword = /\\DDSpoof\\sniffers\\/ nocase ascii wide
                        $string8_DDSpoof_offensive_tool_keyword = /\\sniffers\\sniffer\.py/ nocase ascii wide
                        $string9_DDSpoof_offensive_tool_keyword = /\]\sDHCP\ssniffer\sidentified\spotential\sspoofing\starget\:/ nocase ascii wide
                        $string10_DDSpoof_offensive_tool_keyword = /\]\sDHCP\sSniffer\sidentified\spreviously\ssniffed\sname\:\s/ nocase ascii wide
                        $string11_DDSpoof_offensive_tool_keyword = /\]\sLLMNR\ssniffer\sidentified\spotential\sspoofing\starget\:/ nocase ascii wide
                        $string12_DDSpoof_offensive_tool_keyword = /\]\sLLMNR\sSniffer\sidentified\spreviously\ssniffed\sname/ nocase ascii wide
                        $string13_DDSpoof_offensive_tool_keyword = "akamai/DDSpoof" nocase ascii wide
                        $string14_DDSpoof_offensive_tool_keyword = /ddspoof.{0,1000}\-\-enum\-name\-protection/ nocase ascii wide
                        $string15_DDSpoof_offensive_tool_keyword = /ddspoof\.py\s\-/ nocase ascii wide
                        $string16_DDSpoof_offensive_tool_keyword = /DDSpoof\\spoofer_config\.py/ nocase ascii wide
                        $string17_DDSpoof_offensive_tool_keyword = "DDSpoof-main" nocase ascii wide
                        $string18_DDSpoof_offensive_tool_keyword = /dhcp_sniffer\.py/ nocase ascii wide
                        $string19_DDSpoof_offensive_tool_keyword = /from\snetworking\.dhcp_dns_update_utils/ nocase ascii wide
                        $string20_DDSpoof_offensive_tool_keyword = "from spoofer_config import SpooferConfig" nocase ascii wide
                        $string21_DDSpoof_offensive_tool_keyword = "Invoke-DHCPCheckup" nocase ascii wide
                        $string22_DDSpoof_offensive_tool_keyword = /llmnr_sniffer\.py/ nocase ascii wide
                        $string23_DDSpoof_offensive_tool_keyword = /networking\\dhcp_dns_update_utils\.py/ nocase ascii wide
                        $string24_DDSpoof_offensive_tool_keyword = "Path to a DDSpoof config file to load configuration from" nocase ascii wide
                        $string25_DDSpoof_offensive_tool_keyword = /sniffers\.llmnr_sniffer/ nocase ascii wide
                        $string26_DDSpoof_offensive_tool_keyword = "This option will cause DDSpoof to create DNS records on the server" nocase ascii wide

    condition:
        any of them
}