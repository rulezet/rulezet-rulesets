rule PoshADCS
{
    meta:
        description = "Detection patterns for the tool 'PoshADCS' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PoshADCS"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sADCS\.ps1/ nocase ascii wide
                        $string2 = /\/ADCS\.ps1/ nocase ascii wide
                        $string3 = /\/PoshADCS\.git/ nocase ascii wide
                        $string4 = /\\ADCS\.ps1/ nocase ascii wide
                        $string5 = /\\PoshADCS\-master/ nocase ascii wide
                        $string6 = "156a20924b696b89e6df463edce6afe72bc8348af0c52c399ff5d88e3a9d6e5a" nocase ascii wide
                        $string7 = "cfalta/PoshADCS" nocase ascii wide
                        $string8 = "Convert-ADCSFlag " nocase ascii wide
                        $string9 = "Convert-ADCSPrivateKeyFlag" nocase ascii wide
                        $string10 = "Get-ADCSTemplateACL" nocase ascii wide
                        $string11 = /PoshADCS\-master\.zip/ nocase ascii wide

    condition:
        any of them
}