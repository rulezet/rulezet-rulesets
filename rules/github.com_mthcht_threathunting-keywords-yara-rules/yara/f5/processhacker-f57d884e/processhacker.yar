rule processhacker
{
    meta:
        description = "Detection patterns for the tool 'processhacker' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "processhacker"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\/processhacker\-.{0,1000}\-bin\.zip/ nocase ascii wide
                        $string2 = "/processhacker/files/latest/download" nocase ascii wide
                        $string3 = /\\Process\sHacker\s2\\/ nocase ascii wide
                        $string4 = /processhacker\-.{0,1000}\-sdk\.zip/ nocase ascii wide
                        $string5 = /processhacker\-.{0,1000}\-setup\.exe/ nocase ascii wide
                        $string6 = /processhacker\-.{0,1000}\-src\.zip/ nocase ascii wide
                        $string7 = /ProcessHacker\.exe/ nocase ascii wide
                        $string8 = /ProcessHacker\.sln/ nocase ascii wide

    condition:
        any of them
}