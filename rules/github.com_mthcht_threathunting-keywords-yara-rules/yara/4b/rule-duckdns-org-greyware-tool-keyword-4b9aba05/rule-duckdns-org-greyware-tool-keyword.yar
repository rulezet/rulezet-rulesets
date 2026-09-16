rule rule_duckdns_org_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'duckdns.org' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "duckdns.org"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_duckdns_org_greyware_tool_keyword = /\/DuckDNS\.7z/ nocase ascii wide
                        $string2_duckdns_org_greyware_tool_keyword = /\/DuckDNS\.git/ nocase ascii wide
                        $string3_duckdns_org_greyware_tool_keyword = /\/DuckDNS\.zip\\"/ nocase ascii wide
                        $string4_duckdns_org_greyware_tool_keyword = /\/duckdns\/duck\.log/
                        $string5_duckdns_org_greyware_tool_keyword = /\/duckdns\/duck\.sh/ nocase ascii wide
                        $string6_duckdns_org_greyware_tool_keyword = /\/duckdns\-powershell\.git/ nocase ascii wide
                        $string7_duckdns_org_greyware_tool_keyword = "/opt/duckdns/"
                        $string8_duckdns_org_greyware_tool_keyword = /\\DuckDNS\.cfg/ nocase ascii wide
                        $string9_duckdns_org_greyware_tool_keyword = /\\DuckDNS\.csproj/ nocase ascii wide
                        $string10_duckdns_org_greyware_tool_keyword = /\\DuckDNS\.exe/ nocase ascii wide
                        $string11_duckdns_org_greyware_tool_keyword = /\\DuckDNS\.lnk/ nocase ascii wide
                        $string12_duckdns_org_greyware_tool_keyword = /\\DuckDNS\.sln/ nocase ascii wide
                        $string13_duckdns_org_greyware_tool_keyword = /\\Update\-DuckDNS\.ps1/ nocase ascii wide
                        $string14_duckdns_org_greyware_tool_keyword = "4B9C98F6-AF30-4280-873D-B45C7A7B89EB" nocase ascii wide
                        $string15_duckdns_org_greyware_tool_keyword = "8a35136501dde420ec5f3e88a7906c8c3d63af06621b47513befe8f09db3ed04" nocase ascii wide
                        $string16_duckdns_org_greyware_tool_keyword = "ataylor32/duckdns-powershell" nocase ascii wide
                        $string17_duckdns_org_greyware_tool_keyword = /chmod\s700\sduck\.sh/
                        $string18_duckdns_org_greyware_tool_keyword = /https\:\/\/www\.duckdns\.org\/update\?domains\=/ nocase ascii wide
                        $string19_duckdns_org_greyware_tool_keyword = "jzelinskie/duckdns" nocase ascii wide
                        $string20_duckdns_org_greyware_tool_keyword = "Sending update request to Duck DNS" nocase ascii wide
                        $string21_duckdns_org_greyware_tool_keyword = "XWolfOverride/DuckDNS" nocase ascii wide
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