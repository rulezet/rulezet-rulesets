rule rule_crowdstrike_falcon_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'crowdstrike falcon' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "crowdstrike falcon"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_crowdstrike_falcon_greyware_tool_keyword = "runscript -raw=```curl " nocase ascii wide
                        $string2_crowdstrike_falcon_greyware_tool_keyword = "runscript -raw=```whoami" nocase ascii wide

    condition:
        any of them
}