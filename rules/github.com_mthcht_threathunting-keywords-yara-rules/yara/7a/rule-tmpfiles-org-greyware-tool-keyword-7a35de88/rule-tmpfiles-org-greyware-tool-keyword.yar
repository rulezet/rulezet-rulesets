rule rule_tmpfiles_org_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'tmpfiles.org' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "tmpfiles.org"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_tmpfiles_org_greyware_tool_keyword = /https\:\/\/tmpfiles\.org\/dl\/.{0,1000}\.exe/ nocase ascii wide

    condition:
        any of them
}