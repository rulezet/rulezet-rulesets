rule BackupOperatorToDA
{
    meta:
        description = "Detection patterns for the tool 'BackupOperatorToDA' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BackupOperatorToDA"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/BackupOperatorToDA\.git/ nocase ascii wide
                        $string2 = /\\BackupOperatorToDA/ nocase ascii wide
                        $string3 = "0971A047-A45A-43F4-B7D8-16AC1114B524" nocase ascii wide
                        $string4 = /BackupOperatorToDA\.cpp/ nocase ascii wide
                        $string5 = /BackupOperatorToDA\.exe/ nocase ascii wide
                        $string6 = /BackupOperatorToDA\.sln/ nocase ascii wide
                        $string7 = "BackupOperatorToDA-master" nocase ascii wide
                        $string8 = "mpgn/BackupOperatorToDA" nocase ascii wide
                        $string9 = /secredump\.exe/ nocase ascii wide

    condition:
        any of them
}