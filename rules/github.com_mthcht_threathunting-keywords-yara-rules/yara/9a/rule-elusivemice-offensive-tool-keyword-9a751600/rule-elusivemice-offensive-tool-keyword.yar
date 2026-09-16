rule rule_ElusiveMice_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ElusiveMice' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ElusiveMice"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ElusiveMice_offensive_tool_keyword = /\sbuild_arsenal_kit\.sh/ nocase ascii wide
                        $string2_ElusiveMice_offensive_tool_keyword = /\/build_arsenal_kit\.sh/ nocase ascii wide
                        $string3_ElusiveMice_offensive_tool_keyword = /\/ElusiveMice\.git/ nocase ascii wide
                        $string4_ElusiveMice_offensive_tool_keyword = /\\elusiveMice\.cna/ nocase ascii wide
                        $string5_ElusiveMice_offensive_tool_keyword = "0e2e712fe0bc1ddddc027c85d701be1175a3fc75fddb0a599dcd065d6385e0cb" nocase ascii wide
                        $string6_ElusiveMice_offensive_tool_keyword = "34813bb9fdd3b929c12a273710e37882dc2171e4e910f2f0c82b2501ebc69143" nocase ascii wide
                        $string7_ElusiveMice_offensive_tool_keyword = "63a6adaa32811c62d5749052c03057771fb33ae63a765a0ecc480829442dc91e" nocase ascii wide
                        $string8_ElusiveMice_offensive_tool_keyword = "d9220ac56637a1596427cce73d29ad64dec4669bd600d3c41effc512d15c3b6b" nocase ascii wide
                        $string9_ElusiveMice_offensive_tool_keyword = /elusiveMice\.x64\.o/ nocase ascii wide
                        $string10_ElusiveMice_offensive_tool_keyword = /elusiveMice\.x86\.o/ nocase ascii wide
                        $string11_ElusiveMice_offensive_tool_keyword = "mgeeky/ElusiveMice" nocase ascii wide
                        $string12_ElusiveMice_offensive_tool_keyword = "Running elusiveMice 'BEACON_RDLL_GENERATE" nocase ascii wide

    condition:
        any of them
}