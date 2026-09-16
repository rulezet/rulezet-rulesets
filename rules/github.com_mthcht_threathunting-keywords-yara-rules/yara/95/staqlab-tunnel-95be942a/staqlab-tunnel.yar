rule staqlab_tunnel
{
    meta:
        description = "Detection patterns for the tool 'staqlab-tunnel' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "staqlab-tunnel"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\.\/staqlab\-tunnel\s/
                        $string2 = "/bin/staqlab-tunnel"
                        $string3 = "6510fdf42becdab665232ef6393e40a559dd2b3b2b7927333c9f30a62bf7de3f" nocase ascii wide
                        $string4 = "7ec426ac53bac81654965fa1b8ff8af3451b7524f648d4b11ea7d3437a5ba907" nocase ascii wide
                        $string5 = "d0d66c649a64735a67735370f0790418b48abeccaa0506fa66f00a967e8c3b73" nocase ascii wide
                        $string6 = "staqlab-tunnel port=" nocase ascii wide
                        $string7 = /staqlab\-tunnel\.exe/ nocase ascii wide
                        $string8 = /staqlab\-tunnel\.zip/ nocase ascii wide
                        $string9 = /tunnel\.staqlab\.com/ nocase ascii wide
                        $string10 = /tunnel\-api\.staqlab\.com/ nocase ascii wide

    condition:
        any of them
}