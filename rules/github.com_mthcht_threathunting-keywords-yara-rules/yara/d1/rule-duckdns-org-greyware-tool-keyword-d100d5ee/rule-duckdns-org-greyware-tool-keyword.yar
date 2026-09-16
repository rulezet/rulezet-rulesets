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

    condition:
        any of them
}