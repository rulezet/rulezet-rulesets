rule RpcView
{
    meta:
        description = "Detection patterns for the tool 'RpcView' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RpcView"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\\RpcView\.exe/ nocase ascii wide
                        $string2 = /\\RpcView64\.7z/ nocase ascii wide
                        $string3 = "0d2d07010e3ad3219d37b9a10a04abf50bd84c6c429b96aab5aad70f31c42efe" nocase ascii wide
                        $string4 = "a1d89c9d81a2e9c7558e8f0c91ec8652d40af94726f3125f9fe31206adb528de" nocase ascii wide
                        $string5 = "silverf0x/RpcView" nocase ascii wide

    condition:
        any of them
}