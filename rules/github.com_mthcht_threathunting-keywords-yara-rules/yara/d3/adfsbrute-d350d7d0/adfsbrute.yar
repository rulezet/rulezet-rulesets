rule adfsbrute
{
    meta:
        description = "Detection patterns for the tool 'adfsbrute' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "adfsbrute"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sadfsbrute\.py/ nocase ascii wide
                        $string2 = " --tor_password " nocase ascii wide
                        $string3 = " --userpassword_list " nocase ascii wide
                        $string4 = /\/adfsbrute\.git/ nocase ascii wide
                        $string5 = /\/adfsbrute\.py/ nocase ascii wide
                        $string6 = /\\adfsbrute\.py/ nocase ascii wide
                        $string7 = "d9adb9ecfa37595ce0dd2d8b4841334b32243bd30455fba4f59ce44a33efcdc4" nocase ascii wide
                        $string8 = "ricardojoserf/adfsbrute" nocase ascii wide

    condition:
        any of them
}