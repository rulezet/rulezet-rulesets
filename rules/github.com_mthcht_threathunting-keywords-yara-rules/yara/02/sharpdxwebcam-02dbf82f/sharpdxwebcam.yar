rule SharpDXWebcam
{
    meta:
        description = "Detection patterns for the tool 'SharpDXWebcam' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpDXWebcam"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /Get\-DXWebcamVideo\.ps1/ nocase ascii wide
                        $string2 = "SharpDXWebcam" nocase ascii wide

    condition:
        any of them
}