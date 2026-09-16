rule LinikatzV2
{
    meta:
        description = "Detection patterns for the tool 'LinikatzV2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LinikatzV2"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/LinikatzV2/"
                        $string2 = /\\LinikatzV2\\/
                        $string3 = "kerberos_steal"
                        $string4 = /linikatzV2\.sh/
                        $string5 = "Orange-Cyberdefense/LinikatzV2"
                        $string6 = /SSSDKCMExtractor\.py/

    condition:
        any of them
}