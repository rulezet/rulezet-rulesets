rule MSOLSpray
{
    meta:
        description = "Detection patterns for the tool 'MSOLSpray' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MSOLSpray"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/MSOLSpray" nocase ascii wide
                        $string2 = "MSOLSpray " nocase ascii wide
                        $string3 = /MSOLSpray\.git/ nocase ascii wide
                        $string4 = /MSOLSpray\.ps1/ nocase ascii wide
                        $string5 = "MSOLSpray-master" nocase ascii wide

    condition:
        any of them
}