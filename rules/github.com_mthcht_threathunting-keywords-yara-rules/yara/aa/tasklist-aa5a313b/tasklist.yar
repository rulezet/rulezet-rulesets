rule tasklist
{
    meta:
        description = "Detection patterns for the tool 'tasklist' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "tasklist"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /tasklist\s\/fi\s.{0,1000}Imagename\seq\slsass\.exe/ nocase ascii wide
                        $string2 = /tasklist\s\/svc\s\|\sfindstr\s\/i\s\\"vmtoolsd\.exe\\"/ nocase ascii wide
                        $string3 = /tasklist\s\|\sfindstr\slsass/ nocase ascii wide

    condition:
        any of them
}