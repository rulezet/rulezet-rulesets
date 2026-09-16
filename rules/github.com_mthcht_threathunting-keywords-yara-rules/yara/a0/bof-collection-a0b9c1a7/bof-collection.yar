rule bof_collection
{
    meta:
        description = "Detection patterns for the tool 'bof-collection' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "bof-collection"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "chromiumkeydump " nocase ascii wide
                        $string2 = /ChromiumKeyDump\.cna/ nocase ascii wide
                        $string3 = /ChromiumKeyDump\.cpp/ nocase ascii wide
                        $string4 = /ChromiumKeyDump\.exe/ nocase ascii wide
                        $string5 = "crypt0p3g/bof-collection" nocase ascii wide
                        $string6 = /Minidump\.exe/ nocase ascii wide
                        $string7 = /Minidump\.sln/ nocase ascii wide

    condition:
        any of them
}