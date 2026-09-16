rule rule_transfert_my_files_com_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'transfert-my-files.com' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "transfert-my-files.com"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_transfert_my_files_com_greyware_tool_keyword = /https\:\/\/transfert\-my\-files\.com\/files\// nocase ascii wide
                        $string2_transfert_my_files_com_greyware_tool_keyword = /https\:\/\/transfert\-my\-files\.com\/inc\/upload\.php/ nocase ascii wide

    condition:
        any of them
}