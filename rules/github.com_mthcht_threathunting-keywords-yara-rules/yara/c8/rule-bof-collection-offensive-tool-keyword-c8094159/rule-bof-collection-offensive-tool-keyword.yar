rule rule_bof_collection_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'bof-collection' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "bof-collection"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_bof_collection_offensive_tool_keyword = "chromiumkeydump " nocase ascii wide
                        $string2_bof_collection_offensive_tool_keyword = /ChromiumKeyDump\.cna/ nocase ascii wide
                        $string3_bof_collection_offensive_tool_keyword = /ChromiumKeyDump\.cpp/ nocase ascii wide
                        $string4_bof_collection_offensive_tool_keyword = /ChromiumKeyDump\.exe/ nocase ascii wide
                        $string5_bof_collection_offensive_tool_keyword = "crypt0p3g/bof-collection" nocase ascii wide
                        $string6_bof_collection_offensive_tool_keyword = /Minidump\.exe/ nocase ascii wide
                        $string7_bof_collection_offensive_tool_keyword = /Minidump\.sln/ nocase ascii wide

    condition:
        any of them
}