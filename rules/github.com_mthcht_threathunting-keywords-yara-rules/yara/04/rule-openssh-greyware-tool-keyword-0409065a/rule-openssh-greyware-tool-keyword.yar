rule rule_Openssh_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Openssh' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Openssh"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_Openssh_greyware_tool_keyword = /Add\-WindowsCapability\s\-Online\s\-Name\sOpenSSH\.Server/ nocase ascii wide
                        $string2_Openssh_greyware_tool_keyword = /Import\-Module\s.{0,1000}\\OpenSSHUtils/ nocase ascii wide

    condition:
        any of them
}