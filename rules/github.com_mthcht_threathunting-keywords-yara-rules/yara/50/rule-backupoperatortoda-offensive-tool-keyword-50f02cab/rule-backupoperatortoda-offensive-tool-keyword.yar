rule rule_BackupOperatorToDA_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'BackupOperatorToDA' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BackupOperatorToDA"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_BackupOperatorToDA_offensive_tool_keyword = /\/BackupOperatorToDA\.git/ nocase ascii wide
                        $string2_BackupOperatorToDA_offensive_tool_keyword = /\\BackupOperatorToDA/ nocase ascii wide
                        $string3_BackupOperatorToDA_offensive_tool_keyword = "0971A047-A45A-43F4-B7D8-16AC1114B524" nocase ascii wide
                        $string4_BackupOperatorToDA_offensive_tool_keyword = /BackupOperatorToDA\.cpp/ nocase ascii wide
                        $string5_BackupOperatorToDA_offensive_tool_keyword = /BackupOperatorToDA\.exe/ nocase ascii wide
                        $string6_BackupOperatorToDA_offensive_tool_keyword = /BackupOperatorToDA\.sln/ nocase ascii wide
                        $string7_BackupOperatorToDA_offensive_tool_keyword = "BackupOperatorToDA-master" nocase ascii wide
                        $string8_BackupOperatorToDA_offensive_tool_keyword = "mpgn/BackupOperatorToDA" nocase ascii wide
                        $string9_BackupOperatorToDA_offensive_tool_keyword = /secredump\.exe/ nocase ascii wide

    condition:
        any of them
}