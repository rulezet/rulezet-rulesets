rule rule_COM_Object_hijacking_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'COM-Object-hijacking' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "COM-Object-hijacking"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_COM_Object_hijacking_offensive_tool_keyword = /\/COM\-Object\-hijacking\.git/ nocase ascii wide
                        $string2_COM_Object_hijacking_offensive_tool_keyword = /\\COM\-Object\-hijacking\-master/ nocase ascii wide
                        $string3_COM_Object_hijacking_offensive_tool_keyword = "3gstudent/COM-Object-hijacking" nocase ascii wide
                        $string4_COM_Object_hijacking_offensive_tool_keyword = "ab816e6fa86f08ce0cadd09aa19335b5304f75a55f8fecfe917583650a12fe2c" nocase ascii wide
                        $string5_COM_Object_hijacking_offensive_tool_keyword = /COM\sObject\shijacking\spersistence\.ps1/ nocase ascii wide

    condition:
        any of them
}