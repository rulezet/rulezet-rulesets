rule COM_Object_hijacking
{
    meta:
        description = "Detection patterns for the tool 'COM-Object-hijacking' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "COM-Object-hijacking"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/COM\-Object\-hijacking\.git/ nocase ascii wide
                        $string2 = /\\COM\-Object\-hijacking\-master/ nocase ascii wide
                        $string3 = "3gstudent/COM-Object-hijacking" nocase ascii wide
                        $string4 = "ab816e6fa86f08ce0cadd09aa19335b5304f75a55f8fecfe917583650a12fe2c" nocase ascii wide
                        $string5 = /COM\sObject\shijacking\spersistence\.ps1/ nocase ascii wide

    condition:
        any of them
}