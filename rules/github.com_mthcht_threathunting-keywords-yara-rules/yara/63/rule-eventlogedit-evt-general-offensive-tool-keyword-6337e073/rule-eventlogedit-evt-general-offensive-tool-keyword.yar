rule rule_Eventlogedit_evt__General_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Eventlogedit-evt--General' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Eventlogedit-evt--General"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Eventlogedit_evt__General_offensive_tool_keyword = /\/Eventlogedit\-evt\-\-General\.git/ nocase ascii wide
                        $string2_Eventlogedit_evt__General_offensive_tool_keyword = /\\evtDeleteRecordbyGetHandle\.cpp/ nocase ascii wide
                        $string3_Eventlogedit_evt__General_offensive_tool_keyword = /\\evtDeleteRecordbyGetHandle\.exe/ nocase ascii wide
                        $string4_Eventlogedit_evt__General_offensive_tool_keyword = /\\evtDeleteRecordofFile\.cpp/ nocase ascii wide
                        $string5_Eventlogedit_evt__General_offensive_tool_keyword = /\\evtDeleteRecordofFile\.exe/ nocase ascii wide
                        $string6_Eventlogedit_evt__General_offensive_tool_keyword = /\\evtModifyRecordbyGetHandle\.cpp/ nocase ascii wide
                        $string7_Eventlogedit_evt__General_offensive_tool_keyword = /\\evtModifyRecordbyGetHandle\.exe/ nocase ascii wide
                        $string8_Eventlogedit_evt__General_offensive_tool_keyword = /\\evtQueryRecordbyGetHandle\.cpp/ nocase ascii wide
                        $string9_Eventlogedit_evt__General_offensive_tool_keyword = /\\evtQueryRecordbyGetHandle\.exe/ nocase ascii wide
                        $string10_Eventlogedit_evt__General_offensive_tool_keyword = /3gstudent\.github\.io\/Windows\-Event\-Viewer\-Log\-/ nocase ascii wide
                        $string11_Eventlogedit_evt__General_offensive_tool_keyword = "3gstudent/Eventlogedit-evt--General" nocase ascii wide
                        $string12_Eventlogedit_evt__General_offensive_tool_keyword = "75ae186f6b5f926d7d538642d1258d028eaf404859813c5a0ce53df00115d7ee" nocase ascii wide
                        $string13_Eventlogedit_evt__General_offensive_tool_keyword = "7c43dca2c565e2c362c1085358213802a55f05d911560b689bbd138225e8d6d7" nocase ascii wide
                        $string14_Eventlogedit_evt__General_offensive_tool_keyword = "8613f6bd93b3ef201a4ef71a88d67c78cbbe693f71729eecf58d3ef06306610f" nocase ascii wide
                        $string15_Eventlogedit_evt__General_offensive_tool_keyword = /Delete\sspecified\sevt\sfile\'s\seventlog\srecord\.You\sneed\sto\sset\sStartTime\sand\sEndTime/ nocase ascii wide
                        $string16_Eventlogedit_evt__General_offensive_tool_keyword = /Delete\sspecified\sevt\sfile\'s\seventlog\srecord\.You\sneed\sto\sset\sStartTime\sand\sEndTime/ nocase ascii wide
                        $string17_Eventlogedit_evt__General_offensive_tool_keyword = "eb66eddca2e0c2a6b40ab6be4a159be5c81ee9f1dd3b7cc42df7c017ae06ee45" nocase ascii wide
                        $string18_Eventlogedit_evt__General_offensive_tool_keyword = /Modify\sthe\sselected\srecords\sof\sthe\sWindows\sEvent\sViewer\sLog\s\(EVT/ nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or             uint16(0) == 0x457f or             uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or             uint32(0) == 0x504B0304 or             uint32(0) == 0xCAFEBABE or             uint32(0) == 0x4D534346 or             uint32(0) == 0xD0CF11E0 or             uint16(0) == 0x2321 or             uint16(0) == 0x3c3f         )) and any of ($string*)) or
        (filesize < 2MB and
        (
            any of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}