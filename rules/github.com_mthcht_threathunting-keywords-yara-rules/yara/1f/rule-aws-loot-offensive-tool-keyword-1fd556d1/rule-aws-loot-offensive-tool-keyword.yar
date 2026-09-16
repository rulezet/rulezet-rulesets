rule rule_AWS_Loot_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'AWS-Loot' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AWS-Loot"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_AWS_Loot_offensive_tool_keyword = /\sawsloot\.py/ nocase ascii wide
                        $string2_AWS_Loot_offensive_tool_keyword = /\.\/awsloot\s/
                        $string3_AWS_Loot_offensive_tool_keyword = /\.\/awsloot\.py/
                        $string4_AWS_Loot_offensive_tool_keyword = "/AWS-Loot" nocase ascii wide
                        $string5_AWS_Loot_offensive_tool_keyword = /\/CodeBuildLooter\.py/ nocase ascii wide
                        $string6_AWS_Loot_offensive_tool_keyword = /\/EC2Looter\.py/ nocase ascii wide
                        $string7_AWS_Loot_offensive_tool_keyword = /\/LambdaLooter\.py/ nocase ascii wide
                        $string8_AWS_Loot_offensive_tool_keyword = /awsloot\.py\s/ nocase ascii wide

    condition:
        any of them
}