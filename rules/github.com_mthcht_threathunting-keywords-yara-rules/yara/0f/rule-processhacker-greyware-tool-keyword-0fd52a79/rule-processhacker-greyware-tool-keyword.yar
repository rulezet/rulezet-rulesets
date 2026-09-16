rule rule_processhacker_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'processhacker' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "processhacker"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_processhacker_greyware_tool_keyword = /\/processhacker\-.{0,1000}\-bin\.zip/ nocase ascii wide
                        $string2_processhacker_greyware_tool_keyword = "/processhacker/files/latest/download" nocase ascii wide
                        $string3_processhacker_greyware_tool_keyword = /\\Process\sHacker\s2\\/ nocase ascii wide
                        $string4_processhacker_greyware_tool_keyword = /processhacker\-.{0,1000}\-sdk\.zip/ nocase ascii wide
                        $string5_processhacker_greyware_tool_keyword = /processhacker\-.{0,1000}\-setup\.exe/ nocase ascii wide
                        $string6_processhacker_greyware_tool_keyword = /processhacker\-.{0,1000}\-src\.zip/ nocase ascii wide
                        $string7_processhacker_greyware_tool_keyword = /ProcessHacker\.exe/ nocase ascii wide
                        $string8_processhacker_greyware_tool_keyword = /ProcessHacker\.sln/ nocase ascii wide

    condition:
        any of them
}