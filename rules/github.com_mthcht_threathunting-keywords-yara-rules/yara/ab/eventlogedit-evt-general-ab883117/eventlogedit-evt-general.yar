rule Eventlogedit_evt__General
{
    meta:
        description = "Detection patterns for the tool 'Eventlogedit-evt--General' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Eventlogedit-evt--General"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/Eventlogedit\-evt\-\-General\.git/ nocase ascii wide
                        $string2 = /\\evtDeleteRecordbyGetHandle\.cpp/ nocase ascii wide
                        $string3 = /\\evtDeleteRecordbyGetHandle\.exe/ nocase ascii wide
                        $string4 = /\\evtDeleteRecordofFile\.cpp/ nocase ascii wide
                        $string5 = /\\evtDeleteRecordofFile\.exe/ nocase ascii wide
                        $string6 = /\\evtModifyRecordbyGetHandle\.cpp/ nocase ascii wide
                        $string7 = /\\evtModifyRecordbyGetHandle\.exe/ nocase ascii wide
                        $string8 = /\\evtQueryRecordbyGetHandle\.cpp/ nocase ascii wide
                        $string9 = /\\evtQueryRecordbyGetHandle\.exe/ nocase ascii wide
                        $string10 = /3gstudent\.github\.io\/Windows\-Event\-Viewer\-Log\-/ nocase ascii wide
                        $string11 = "3gstudent/Eventlogedit-evt--General" nocase ascii wide
                        $string12 = "75ae186f6b5f926d7d538642d1258d028eaf404859813c5a0ce53df00115d7ee" nocase ascii wide
                        $string13 = "7c43dca2c565e2c362c1085358213802a55f05d911560b689bbd138225e8d6d7" nocase ascii wide
                        $string14 = "8613f6bd93b3ef201a4ef71a88d67c78cbbe693f71729eecf58d3ef06306610f" nocase ascii wide
                        $string15 = /Delete\sspecified\sevt\sfile\'s\seventlog\srecord\.You\sneed\sto\sset\sStartTime\sand\sEndTime/ nocase ascii wide
                        $string16 = /Delete\sspecified\sevt\sfile\'s\seventlog\srecord\.You\sneed\sto\sset\sStartTime\sand\sEndTime/ nocase ascii wide
                        $string17 = "eb66eddca2e0c2a6b40ab6be4a159be5c81ee9f1dd3b7cc42df7c017ae06ee45" nocase ascii wide
                        $string18 = /Modify\sthe\sselected\srecords\sof\sthe\sWindows\sEvent\sViewer\sLog\s\(EVT/ nocase ascii wide

    condition:
        any of them
}