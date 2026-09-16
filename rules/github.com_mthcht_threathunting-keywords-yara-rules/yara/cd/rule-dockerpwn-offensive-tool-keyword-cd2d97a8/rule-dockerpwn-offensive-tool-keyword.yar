rule rule_DockerPwn_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'DockerPwn' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DockerPwn"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_DockerPwn_offensive_tool_keyword = "DockerPwn" nocase ascii wide

    condition:
        any of them
}