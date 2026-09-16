rule DDSpoof
{
    meta:
        description = "Detection patterns for the tool 'DDSpoof' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DDSpoof"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sddspoof\.py/ nocase ascii wide
                        $string2 = /\sdhcp_dns_update_utils\.py/ nocase ascii wide
                        $string3 = /\/DDSpoof\.git/ nocase ascii wide
                        $string4 = /\/ddspoof\.py/ nocase ascii wide
                        $string5 = /\\ddspoof\.py/ nocase ascii wide
                        $string6 = /\\DDSpoof\\networking\\/ nocase ascii wide
                        $string7 = /\\DDSpoof\\sniffers\\/ nocase ascii wide
                        $string8 = /\\sniffers\\sniffer\.py/ nocase ascii wide
                        $string9 = /\]\sDHCP\ssniffer\sidentified\spotential\sspoofing\starget\:/ nocase ascii wide
                        $string10 = /\]\sDHCP\sSniffer\sidentified\spreviously\ssniffed\sname\:\s/ nocase ascii wide
                        $string11 = /\]\sLLMNR\ssniffer\sidentified\spotential\sspoofing\starget\:/ nocase ascii wide
                        $string12 = /\]\sLLMNR\sSniffer\sidentified\spreviously\ssniffed\sname/ nocase ascii wide
                        $string13 = "akamai/DDSpoof" nocase ascii wide
                        $string14 = /ddspoof.{0,1000}\-\-enum\-name\-protection/ nocase ascii wide
                        $string15 = /ddspoof\.py\s\-/ nocase ascii wide
                        $string16 = /DDSpoof\\spoofer_config\.py/ nocase ascii wide
                        $string17 = "DDSpoof-main" nocase ascii wide
                        $string18 = /dhcp_sniffer\.py/ nocase ascii wide
                        $string19 = /from\snetworking\.dhcp_dns_update_utils/ nocase ascii wide
                        $string20 = "from spoofer_config import SpooferConfig" nocase ascii wide
                        $string21 = "Invoke-DHCPCheckup" nocase ascii wide
                        $string22 = /llmnr_sniffer\.py/ nocase ascii wide
                        $string23 = /networking\\dhcp_dns_update_utils\.py/ nocase ascii wide
                        $string24 = "Path to a DDSpoof config file to load configuration from" nocase ascii wide
                        $string25 = /sniffers\.llmnr_sniffer/ nocase ascii wide
                        $string26 = "This option will cause DDSpoof to create DNS records on the server" nocase ascii wide

    condition:
        any of them
}