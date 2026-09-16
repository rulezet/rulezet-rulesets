rule rundll32
{
    meta:
        description = "Detection patterns for the tool 'rundll32' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "rundll32"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /comsvcs\.dll\,\sMiniDump\s/ nocase ascii wide
                        $string2 = /comsvcs\.dll\,\#24\s/ nocase ascii wide
                        $string3 = /lsass.{0,1000}rundll32\.exe\s.{0,1000}comsvcs\.dll\,\sMiniDump\s.{0,1000}\.dmp\sfull/ nocase ascii wide
                        $string4 = /rundll32.{0,1000}\.dll.{0,1000}a.{0,1000}\/p\:/ nocase ascii wide
                        $string5 = /rundll32.{0,1000}\.dll.{0,1000}StartW/ nocase ascii wide
                        $string6 = /rundll32.{0,1000}comsvcs\.dll\sMiniDump\s/ nocase ascii wide
                        $string7 = /rundll32\.exe\s.{0,1000}comsvcs\.dll\,\sMiniDump\s.{0,1000}lsass.{0,1000}full/ nocase ascii wide

    condition:
        any of them
}