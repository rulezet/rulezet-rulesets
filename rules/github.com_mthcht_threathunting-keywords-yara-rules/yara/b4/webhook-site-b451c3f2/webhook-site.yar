rule webhook_site
{
    meta:
        description = "Detection patterns for the tool 'webhook.site' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "webhook.site"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\/webhook\.site\.git/ nocase ascii wide
                        $string2 = /\@email\.webhook\.site/ nocase ascii wide
                        $string3 = /https\:\/\/webhook\.site\/.{0,1000}\-.{0,1000}\-.{0,1000}\-/ nocase ascii wide
                        $string4 = /webhooksite\/webhook\.site/ nocase ascii wide
                        $string5 = /whcli\sforward\s\-\-token\=.{0,1000}\-.{0,1000}\-.{0,1000}\s\-\-target\=https\:\/\/localhost/

    condition:
        any of them
}