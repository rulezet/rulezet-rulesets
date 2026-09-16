rule atnow
{
    meta:
        description = "Detection patterns for the tool 'atnow' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "atnow"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\/atnow\.exe/ nocase ascii wide
                        $string2 = /\/atnow\.zip/ nocase ascii wide
                        $string3 = /\\AtNow\s\\\\/ nocase ascii wide
                        $string4 = /\\atnow\.exe/ nocase ascii wide
                        $string5 = /\\atnow\.zip/ nocase ascii wide
                        $string6 = ">Near-Future Command Scheduler<" nocase ascii wide
                        $string7 = "aa142160446a919eaba99ce15992f6e11b1fdaa7a9f569979a29068120f774cf" nocase ascii wide
                        $string8 = /ProductName.{0,1000}\>AtNow\</ nocase ascii wide

    condition:
        any of them
}