rule rule_temp_mail_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'temp-mail' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "temp-mail"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_temp_mail_greyware_tool_keyword = /https\:\/\/privatix\-temp\-mail\-v1\.p\.rapidapi\.com\/request\/domains\// nocase ascii wide
                        $string2_temp_mail_greyware_tool_keyword = /https\:\/\/privatix\-temp\-mail\-v1\.p\.rapidapi\.com\/request\/mail\/id\/null\// nocase ascii wide

    condition:
        any of them
}