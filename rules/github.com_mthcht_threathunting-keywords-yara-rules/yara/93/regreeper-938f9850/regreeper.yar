rule regreeper
{
    meta:
        description = "Detection patterns for the tool 'regreeper' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "regreeper"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/regreeper\.jpg/ nocase ascii wide
                        $string2 = "/Reg-Restore-Persistence-Mole" nocase ascii wide
                        $string3 = /\\save_reg\.hive/ nocase ascii wide
                        $string4 = "A7AD39B5-9BA1-48A9-B928-CA25FDD8F31F" nocase ascii wide
                        $string5 = /RegReeper\.7z/ nocase ascii wide
                        $string6 = /RegReeper\.cpp/ nocase ascii wide
                        $string7 = /RegReeper\.exe/ nocase ascii wide
                        $string8 = /RegReeper\.sln/ nocase ascii wide
                        $string9 = /RegReeper\.vcxproj/ nocase ascii wide
                        $string10 = "Reg-Restore-Persistence-Mole-main" nocase ascii wide

    condition:
        any of them
}