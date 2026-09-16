rule duckdns_org
{
    meta:
        description = "Detection patterns for the tool 'duckdns.org' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "duckdns.org"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\/DuckDNS\.7z/ nocase ascii wide
                        $string2 = /\/DuckDNS\.git/ nocase ascii wide
                        $string3 = /\/DuckDNS\.zip\\"/ nocase ascii wide
                        $string4 = /\/duckdns\/duck\.log/
                        $string5 = /\/duckdns\/duck\.sh/ nocase ascii wide
                        $string6 = /\/duckdns\-powershell\.git/ nocase ascii wide
                        $string7 = "/opt/duckdns/"
                        $string8 = /\\DuckDNS\.cfg/ nocase ascii wide
                        $string9 = /\\DuckDNS\.csproj/ nocase ascii wide
                        $string10 = /\\DuckDNS\.exe/ nocase ascii wide
                        $string11 = /\\DuckDNS\.lnk/ nocase ascii wide
                        $string12 = /\\DuckDNS\.sln/ nocase ascii wide
                        $string13 = /\\Update\-DuckDNS\.ps1/ nocase ascii wide
                        $string14 = "4B9C98F6-AF30-4280-873D-B45C7A7B89EB" nocase ascii wide
                        $string15 = "8a35136501dde420ec5f3e88a7906c8c3d63af06621b47513befe8f09db3ed04" nocase ascii wide
                        $string16 = "ataylor32/duckdns-powershell" nocase ascii wide
                        $string17 = /chmod\s700\sduck\.sh/
                        $string18 = /https\:\/\/www\.duckdns\.org\/update\?domains\=/ nocase ascii wide
                        $string19 = "jzelinskie/duckdns" nocase ascii wide
                        $string20 = "Sending update request to Duck DNS" nocase ascii wide
                        $string21 = "XWolfOverride/DuckDNS" nocase ascii wide

    condition:
        any of them
}