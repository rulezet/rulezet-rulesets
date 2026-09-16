rule cracklord
{
    meta:
        description = "Detection patterns for the tool 'cracklord' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "cracklord"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/cracklord\.git/ nocase ascii wide
                        $string2 = "/cracklord/cmd/" nocase ascii wide
                        $string3 = /cracklord\-master\./ nocase ascii wide
                        $string4 = /cracklord\-queued.{0,1000}_amd64\.deb/ nocase ascii wide
                        $string5 = /cracklord\-resourced.{0,1000}_amd64\.deb/ nocase ascii wide
                        $string6 = "jmmcatee/cracklord" nocase ascii wide

    condition:
        any of them
}