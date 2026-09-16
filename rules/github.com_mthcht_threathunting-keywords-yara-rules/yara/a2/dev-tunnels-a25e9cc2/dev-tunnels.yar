rule dev_tunnels
{
    meta:
        description = "Detection patterns for the tool 'dev-tunnels' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dev-tunnels"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\shost\s\-p\s.{0,100}\s\-\-allow\-anonymous\s\-\-protocol\shttps/ nocase ascii wide
                        $string2 = " host -p 443 -allow-anonymous" nocase ascii wide
                        $string3 = /\.asse\.devtunnels\.ms/ nocase ascii wide
                        $string4 = /\.exe\shost\s\-p\s.{0,100}\s\-\sallow\-anonymous/ nocase ascii wide
                        $string5 = /\.exe\sport\screate\s\-p\s/ nocase ascii wide
                        $string6 = /\\devtunnel\.dll/ nocase ascii wide
                        $string7 = /\\tunnel\-service\.log/ nocase ascii wide
                        $string8 = /\>devtunnel\.dll\</ nocase ascii wide
                        $string9 = /\-443\.devtunnels\.ms/ nocase ascii wide
                        $string10 = /asse\.rel\.tunnels\.api\.visualstudio\.com/ nocase ascii wide
                        $string11 = /auc1\.rel\.tunnels\.api\.visualstudio\.com/ nocase ascii wide
                        $string12 = /aue\.rel\.tunnels\.api\.visualstudio\.com/ nocase ascii wide
                        $string13 = /brs\.rel\.tunnels\.api\.visualstudio\.com/ nocase ascii wide
                        $string14 = "devtunnel create " nocase ascii wide
                        $string15 = "devtunnel host -p " nocase ascii wide
                        $string16 = "devtunnel user login" nocase ascii wide
                        $string17 = /devtunnel.{0,100}\suser\slogin\s\-/ nocase ascii wide
                        $string18 = /devtunnel\.exe\s/ nocase ascii wide
                        $string19 = /devtunnel\.exe.{0,100}host\s\-p\s/ nocase ascii wide
                        $string20 = /eun1\.rel\.tunnels\.api\.visualstudio\.com/ nocase ascii wide
                        $string21 = /euw\.rel\.tunnels\.api\.visualstudio\.com/ nocase ascii wide
                        $string22 = /global\.rel\.tunnels\.api\.visualstudio\.com/ nocase ascii wide
                        $string23 = /https\:\/\/.{0,100}\..{0,100}\.devtunnels\.ms/ nocase ascii wide
                        $string24 = /https\:\/\/.{0,100}\.brs\.devtunnels\.ms\// nocase ascii wide
                        $string25 = /https\:\/\/.{0,100}\.euw\.devtunnels\.ms/ nocase ascii wide
                        $string26 = /https\:\/\/.{0,100}\.use\.devtunnels\.ms/ nocase ascii wide
                        $string27 = /https\:\/\/aka\.ms\/DevTunnelCliInstall/ nocase ascii wide
                        $string28 = /https\:\/\/aka\.ms\/TunnelsCliDownload\// nocase ascii wide
                        $string29 = /inc1\.rel\.tunnels\.api\.visualstudio\.com/ nocase ascii wide
                        $string30 = /Microsoft\.DevTunnels\.Connections\.dll/ nocase ascii wide
                        $string31 = /Microsoft\.DevTunnels\.Contracts\.dll/ nocase ascii wide
                        $string32 = /Microsoft\.DevTunnels\.Management\.dll/ nocase ascii wide
                        $string33 = /Microsoft\.DevTunnels\.Ssh\.dll/ nocase ascii wide
                        $string34 = /Microsoft\.DevTunnels\.Ssh\.Tcp\.dll/ nocase ascii wide
                        $string35 = /ssh\s\@ssh\..{0,100}\.devtunnels\.ms/ nocase ascii wide
                        $string36 = /tunnels\-prod\-rel\-tm\.trafficmanager\.net/ nocase ascii wide
                        $string37 = /tunnels\-prod\-rel\-tm\.trafficmanager\.net/ nocase ascii wide
                        $string38 = /uks1\.rel\.tunnels\.api\.visualstudio\.com/ nocase ascii wide
                        $string39 = /use\.rel\.tunnels\.api\.visualstudio\.com/ nocase ascii wide
                        $string40 = /use2\.rel\.tunnels\.api\.visualstudio\.com/ nocase ascii wide
                        $string41 = /usw2\.rel\.tunnels\.api\.visualstudio\.com/ nocase ascii wide
                        $string42 = /usw3\.rel\.tunnels\.api\.visualstudio\.com/ nocase ascii wide
                        $string43 = /wss\:\/\/.{0,100}\.tunnels\.api\.visualstudio\.com\/api\/v1\/Connect\// nocase ascii wide
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