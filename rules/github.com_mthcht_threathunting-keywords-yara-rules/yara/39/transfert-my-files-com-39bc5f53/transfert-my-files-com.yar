rule transfert_my_files_com
{
    meta:
        description = "Detection patterns for the tool 'transfert-my-files.com' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "transfert-my-files.com"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /https\:\/\/transfert\-my\-files\.com\/files\// nocase ascii wide
                        $string2 = /https\:\/\/transfert\-my\-files\.com\/inc\/upload\.php/ nocase ascii wide

    condition:
        any of them
}