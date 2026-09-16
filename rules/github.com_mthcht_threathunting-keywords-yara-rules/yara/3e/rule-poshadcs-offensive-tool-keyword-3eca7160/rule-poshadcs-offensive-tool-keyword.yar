rule rule_PoshADCS_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'PoshADCS' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PoshADCS"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_PoshADCS_offensive_tool_keyword = /\sADCS\.ps1/ nocase ascii wide
                        $string2_PoshADCS_offensive_tool_keyword = /\/ADCS\.ps1/ nocase ascii wide
                        $string3_PoshADCS_offensive_tool_keyword = /\/PoshADCS\.git/ nocase ascii wide
                        $string4_PoshADCS_offensive_tool_keyword = /\\ADCS\.ps1/ nocase ascii wide
                        $string5_PoshADCS_offensive_tool_keyword = /\\PoshADCS\-master/ nocase ascii wide
                        $string6_PoshADCS_offensive_tool_keyword = "156a20924b696b89e6df463edce6afe72bc8348af0c52c399ff5d88e3a9d6e5a" nocase ascii wide
                        $string7_PoshADCS_offensive_tool_keyword = "cfalta/PoshADCS" nocase ascii wide
                        $string8_PoshADCS_offensive_tool_keyword = "Convert-ADCSFlag " nocase ascii wide
                        $string9_PoshADCS_offensive_tool_keyword = "Convert-ADCSPrivateKeyFlag" nocase ascii wide
                        $string10_PoshADCS_offensive_tool_keyword = "Get-ADCSTemplateACL" nocase ascii wide
                        $string11_PoshADCS_offensive_tool_keyword = /PoshADCS\-master\.zip/ nocase ascii wide

    condition:
        any of them
}