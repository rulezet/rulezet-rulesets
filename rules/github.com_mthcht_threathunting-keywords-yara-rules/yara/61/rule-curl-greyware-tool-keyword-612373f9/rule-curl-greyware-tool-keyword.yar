rule rule_curl_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'curl' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "curl"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_curl_greyware_tool_keyword = /cmd\.exe.{0,1000}\s\/c\secho\scurl\shttps\:\/\/.{0,1000}\s\-\-output\s\\"\%temp\%.{0,1000}\s\-\-ssl\sno\-revoke\s\-\-insecure\s\-\-location\s\>\s\\"\%temp\%/ nocase ascii wide
                        $string2_curl_greyware_tool_keyword = /curl\shttp\:\/\/.{0,1000}\.png\s\-k\|dd\sskip\=2446\sbs\=1\|sh/
                        $string3_curl_greyware_tool_keyword = /curl\shttps\:\/\/.{0,1000}\.png\s\-k\|dd\sskip\=2446\sbs\=1\|sh/

    condition:
        any of them
}