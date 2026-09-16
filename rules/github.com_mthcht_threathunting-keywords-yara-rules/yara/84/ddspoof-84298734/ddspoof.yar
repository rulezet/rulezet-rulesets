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
                        $string14 = /ddspoof.{0,100}\-\-enum\-name\-protection/ nocase ascii wide
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
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or             uint16(0) == 0x457f or             uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or             uint32(0) == 0x504B0304 or             uint32(0) == 0xCAFEBABE or             uint32(0) == 0x4D534346 or             uint32(0) == 0xD0CF11E0 or             uint16(0) == 0x2321 or             uint16(0) == 0x3c3f         )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}