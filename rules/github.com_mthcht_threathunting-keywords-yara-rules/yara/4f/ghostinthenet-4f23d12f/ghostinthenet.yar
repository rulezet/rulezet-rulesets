rule GhostInTheNet
{
    meta:
        description = "Detection patterns for the tool 'GhostInTheNet' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GhostInTheNet"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/GhostInTheNet\.git/
                        $string2 = /\/GhostInTheNet\.sh/
                        $string3 = "/GhostInTheNet-master"
                        $string4 = /\/tmp\/host\.ghost/
                        $string5 = /\/tmp\/mac\.ghost/
                        $string6 = "GhostInTheNet off"
                        $string7 = "GhostInTheNet on"
                        $string8 = /GhostInTheNet\.sh\s/

    condition:
        any of them
}