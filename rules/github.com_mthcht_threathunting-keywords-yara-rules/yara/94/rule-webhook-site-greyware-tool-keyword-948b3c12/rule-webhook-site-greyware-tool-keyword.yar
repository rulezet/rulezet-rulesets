rule rule_webhook_site_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'webhook.site' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "webhook.site"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_webhook_site_greyware_tool_keyword = /\/webhook\.site\.git/ nocase ascii wide
                        $string2_webhook_site_greyware_tool_keyword = /\@email\.webhook\.site/ nocase ascii wide
                        $string3_webhook_site_greyware_tool_keyword = /https\:\/\/webhook\.site\/.{0,1000}\-.{0,1000}\-.{0,1000}\-/ nocase ascii wide
                        $string4_webhook_site_greyware_tool_keyword = /webhooksite\/webhook\.site/ nocase ascii wide
                        $string5_webhook_site_greyware_tool_keyword = /whcli\sforward\s\-\-token\=.{0,1000}\-.{0,1000}\-.{0,1000}\s\-\-target\=https\:\/\/localhost/

    condition:
        any of them
}