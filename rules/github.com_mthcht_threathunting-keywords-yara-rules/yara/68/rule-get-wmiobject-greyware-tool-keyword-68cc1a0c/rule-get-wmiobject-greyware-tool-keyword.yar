rule rule_Get_WmiObject_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Get-WmiObject' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Get-WmiObject"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_Get_WmiObject_greyware_tool_keyword = /Get\-WmiObject\s\-class\sSMS_Authority\s\-namespace\sroot\\CCM/ nocase ascii wide
                        $string2_Get_WmiObject_greyware_tool_keyword = /Get\-WmiObject\s\-Namespace\s\\"root\\directory\\ldap\\"\s\-Class\sds_user\s/ nocase ascii wide
                        $string3_Get_WmiObject_greyware_tool_keyword = "Get-WmiObject win32_loggedonuser -ComputerName " nocase ascii wide

    condition:
        any of them
}