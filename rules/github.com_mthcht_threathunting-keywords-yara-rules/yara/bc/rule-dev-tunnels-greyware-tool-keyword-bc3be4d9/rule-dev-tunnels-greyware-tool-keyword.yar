rule rule_dev_tunnels_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'dev-tunnels' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dev-tunnels"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_dev_tunnels_greyware_tool_keyword = /\shost\s\-p\s.{0,100}\s\-\-allow\-anonymous\s\-\-protocol\shttps/ nocase ascii wide
                        $string2_dev_tunnels_greyware_tool_keyword = " host -p 443 -allow-anonymous" nocase ascii wide
                        $string3_dev_tunnels_greyware_tool_keyword = /\.asse\.devtunnels\.ms/ nocase ascii wide
                        $string4_dev_tunnels_greyware_tool_keyword = /\.exe\shost\s\-p\s.{0,100}\s\-\sallow\-anonymous/ nocase ascii wide
                        $string5_dev_tunnels_greyware_tool_keyword = /\.exe\sport\screate\s\-p\s/ nocase ascii wide
                        $string6_dev_tunnels_greyware_tool_keyword = /\\devtunnel\.dll/ nocase ascii wide
                        $string7_dev_tunnels_greyware_tool_keyword = /\\tunnel\-service\.log/ nocase ascii wide
                        $string8_dev_tunnels_greyware_tool_keyword = /\>devtunnel\.dll\</ nocase ascii wide
                        $string9_dev_tunnels_greyware_tool_keyword = /\-443\.devtunnels\.ms/ nocase ascii wide
                        $string10_dev_tunnels_greyware_tool_keyword = /asse\.rel\.tunnels\.api\.visualstudio\.com/ nocase ascii wide
                        $string11_dev_tunnels_greyware_tool_keyword = /auc1\.rel\.tunnels\.api\.visualstudio\.com/ nocase ascii wide
                        $string12_dev_tunnels_greyware_tool_keyword = /aue\.rel\.tunnels\.api\.visualstudio\.com/ nocase ascii wide
                        $string13_dev_tunnels_greyware_tool_keyword = /brs\.rel\.tunnels\.api\.visualstudio\.com/ nocase ascii wide
                        $string14_dev_tunnels_greyware_tool_keyword = "devtunnel create " nocase ascii wide
                        $string15_dev_tunnels_greyware_tool_keyword = "devtunnel host -p " nocase ascii wide
                        $string16_dev_tunnels_greyware_tool_keyword = "devtunnel user login" nocase ascii wide
                        $string17_dev_tunnels_greyware_tool_keyword = /devtunnel.{0,100}\suser\slogin\s\-/ nocase ascii wide
                        $string18_dev_tunnels_greyware_tool_keyword = /devtunnel\.exe\s/ nocase ascii wide
                        $string19_dev_tunnels_greyware_tool_keyword = /devtunnel\.exe.{0,100}host\s\-p\s/ nocase ascii wide
                        $string20_dev_tunnels_greyware_tool_keyword = /eun1\.rel\.tunnels\.api\.visualstudio\.com/ nocase ascii wide
                        $string21_dev_tunnels_greyware_tool_keyword = /euw\.rel\.tunnels\.api\.visualstudio\.com/ nocase ascii wide
                        $string22_dev_tunnels_greyware_tool_keyword = /global\.rel\.tunnels\.api\.visualstudio\.com/ nocase ascii wide
                        $string23_dev_tunnels_greyware_tool_keyword = /https\:\/\/.{0,100}\..{0,100}\.devtunnels\.ms/ nocase ascii wide
                        $string24_dev_tunnels_greyware_tool_keyword = /https\:\/\/.{0,100}\.brs\.devtunnels\.ms\// nocase ascii wide
                        $string25_dev_tunnels_greyware_tool_keyword = /https\:\/\/.{0,100}\.euw\.devtunnels\.ms/ nocase ascii wide
                        $string26_dev_tunnels_greyware_tool_keyword = /https\:\/\/.{0,100}\.use\.devtunnels\.ms/ nocase ascii wide
                        $string27_dev_tunnels_greyware_tool_keyword = /https\:\/\/aka\.ms\/DevTunnelCliInstall/ nocase ascii wide
                        $string28_dev_tunnels_greyware_tool_keyword = /https\:\/\/aka\.ms\/TunnelsCliDownload\// nocase ascii wide
                        $string29_dev_tunnels_greyware_tool_keyword = /inc1\.rel\.tunnels\.api\.visualstudio\.com/ nocase ascii wide
                        $string30_dev_tunnels_greyware_tool_keyword = /Microsoft\.DevTunnels\.Connections\.dll/ nocase ascii wide
                        $string31_dev_tunnels_greyware_tool_keyword = /Microsoft\.DevTunnels\.Contracts\.dll/ nocase ascii wide
                        $string32_dev_tunnels_greyware_tool_keyword = /Microsoft\.DevTunnels\.Management\.dll/ nocase ascii wide
                        $string33_dev_tunnels_greyware_tool_keyword = /Microsoft\.DevTunnels\.Ssh\.dll/ nocase ascii wide
                        $string34_dev_tunnels_greyware_tool_keyword = /Microsoft\.DevTunnels\.Ssh\.Tcp\.dll/ nocase ascii wide
                        $string35_dev_tunnels_greyware_tool_keyword = /ssh\s\@ssh\..{0,100}\.devtunnels\.ms/ nocase ascii wide
                        $string36_dev_tunnels_greyware_tool_keyword = /tunnels\-prod\-rel\-tm\.trafficmanager\.net/ nocase ascii wide
                        $string37_dev_tunnels_greyware_tool_keyword = /tunnels\-prod\-rel\-tm\.trafficmanager\.net/ nocase ascii wide
                        $string38_dev_tunnels_greyware_tool_keyword = /uks1\.rel\.tunnels\.api\.visualstudio\.com/ nocase ascii wide
                        $string39_dev_tunnels_greyware_tool_keyword = /use\.rel\.tunnels\.api\.visualstudio\.com/ nocase ascii wide
                        $string40_dev_tunnels_greyware_tool_keyword = /use2\.rel\.tunnels\.api\.visualstudio\.com/ nocase ascii wide
                        $string41_dev_tunnels_greyware_tool_keyword = /usw2\.rel\.tunnels\.api\.visualstudio\.com/ nocase ascii wide
                        $string42_dev_tunnels_greyware_tool_keyword = /usw3\.rel\.tunnels\.api\.visualstudio\.com/ nocase ascii wide
                        $string43_dev_tunnels_greyware_tool_keyword = /wss\:\/\/.{0,100}\.tunnels\.api\.visualstudio\.com\/api\/v1\/Connect\// nocase ascii wide
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