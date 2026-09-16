rule rule_OffensiveNotion_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'OffensiveNotion' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "OffensiveNotion"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_OffensiveNotion_offensive_tool_keyword = /\s\/create\s\/tn\sNotion\s\/tr\s\\.{0,1000}cmd\.exe.{0,1000}\s\-c\s.{0,1000}\\.{0,1000}\s\/sc\sonlogon\s\/ru\sSystem\\/ nocase ascii wide
                        $string2_OffensiveNotion_offensive_tool_keyword = /\$FilterArgs\s\=\s\@\{\sname\=\'Notion\'.{0,1000}EventNameSpace\=\'root\\\\CimV2\'.{0,1000}QueryLanguage\=.{0,1000}WQL.{0,1000}\sQuery\=.{0,1000}SELECT\s.{0,1000}\sFROM\s__InstanceModificationE/ nocase ascii wide
                        $string3_OffensiveNotion_offensive_tool_keyword = /\/OffensiveNotion\.git/ nocase ascii wide
                        $string4_OffensiveNotion_offensive_tool_keyword = "/OffensiveNotion/agent" nocase ascii wide
                        $string5_OffensiveNotion_offensive_tool_keyword = "/OffensiveNotion/osxcross/target/bin" nocase ascii wide
                        $string6_OffensiveNotion_offensive_tool_keyword = "/OffensiveNotion/utils"
                        $string7_OffensiveNotion_offensive_tool_keyword = "cddownloadelevategetprivsinjectpersistportscanpspwdrunassaveshellshutdownsleep" nocase ascii wide
                        $string8_OffensiveNotion_offensive_tool_keyword = "mttaggart/OffensiveNotion" nocase ascii wide
                        $string9_OffensiveNotion_offensive_tool_keyword = /offensive_notion\.exe/ nocase ascii wide
                        $string10_OffensiveNotion_offensive_tool_keyword = "offensive_notion_darwin_"
                        $string11_OffensiveNotion_offensive_tool_keyword = "offensive_notion_linux_"
                        $string12_OffensiveNotion_offensive_tool_keyword = /offensive_notion_win_.{0,1000}\.exe/ nocase ascii wide

    condition:
        any of them
}