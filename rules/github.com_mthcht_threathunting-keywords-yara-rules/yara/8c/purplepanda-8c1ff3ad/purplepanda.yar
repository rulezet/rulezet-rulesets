rule PurplePanda
{
    meta:
        description = "Detection patterns for the tool 'PurplePanda' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PurplePanda"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "carlospolop/PurplePanda" nocase ascii wide
                        $string2 = "cd PurplePanda" nocase ascii wide
                        $string3 = /\-e\s\-\-enumerate\sgoogle.{0,1000}github.{0,1000}k8s\s\-\-github\-only\-org\s\-\-k8s\-get\-secret\-values\s\-\-gcp\-get\-secret\-values/ nocase ascii wide
                        $string4 = /purplepanda\.py/ nocase ascii wide
                        $string5 = /purplepanda_config\.py/ nocase ascii wide
                        $string6 = /purplepanda_github\.py/ nocase ascii wide
                        $string7 = "PURPLEPANDA_NEO4J_URL=" nocase ascii wide
                        $string8 = /purplepanda_prints\.py/ nocase ascii wide
                        $string9 = "PURPLEPANDA_PWD=" nocase ascii wide

    condition:
        any of them
}