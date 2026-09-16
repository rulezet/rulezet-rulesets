rule rule_PurplePanda_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'PurplePanda' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PurplePanda"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_PurplePanda_offensive_tool_keyword = "carlospolop/PurplePanda" nocase ascii wide
                        $string2_PurplePanda_offensive_tool_keyword = "cd PurplePanda" nocase ascii wide
                        $string3_PurplePanda_offensive_tool_keyword = /\-e\s\-\-enumerate\sgoogle.{0,1000}github.{0,1000}k8s\s\-\-github\-only\-org\s\-\-k8s\-get\-secret\-values\s\-\-gcp\-get\-secret\-values/ nocase ascii wide
                        $string4_PurplePanda_offensive_tool_keyword = /purplepanda\.py/ nocase ascii wide
                        $string5_PurplePanda_offensive_tool_keyword = /purplepanda_config\.py/ nocase ascii wide
                        $string6_PurplePanda_offensive_tool_keyword = /purplepanda_github\.py/ nocase ascii wide
                        $string7_PurplePanda_offensive_tool_keyword = "PURPLEPANDA_NEO4J_URL=" nocase ascii wide
                        $string8_PurplePanda_offensive_tool_keyword = /purplepanda_prints\.py/ nocase ascii wide
                        $string9_PurplePanda_offensive_tool_keyword = "PURPLEPANDA_PWD=" nocase ascii wide

    condition:
        any of them
}