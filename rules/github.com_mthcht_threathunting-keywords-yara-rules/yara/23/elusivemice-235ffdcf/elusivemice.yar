rule ElusiveMice
{
    meta:
        description = "Detection patterns for the tool 'ElusiveMice' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ElusiveMice"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sbuild_arsenal_kit\.sh/ nocase ascii wide
                        $string2 = /\/build_arsenal_kit\.sh/ nocase ascii wide
                        $string3 = /\/ElusiveMice\.git/ nocase ascii wide
                        $string4 = /\\elusiveMice\.cna/ nocase ascii wide
                        $string5 = "0e2e712fe0bc1ddddc027c85d701be1175a3fc75fddb0a599dcd065d6385e0cb" nocase ascii wide
                        $string6 = "34813bb9fdd3b929c12a273710e37882dc2171e4e910f2f0c82b2501ebc69143" nocase ascii wide
                        $string7 = "63a6adaa32811c62d5749052c03057771fb33ae63a765a0ecc480829442dc91e" nocase ascii wide
                        $string8 = "d9220ac56637a1596427cce73d29ad64dec4669bd600d3c41effc512d15c3b6b" nocase ascii wide
                        $string9 = /elusiveMice\.x64\.o/ nocase ascii wide
                        $string10 = /elusiveMice\.x86\.o/ nocase ascii wide
                        $string11 = "mgeeky/ElusiveMice" nocase ascii wide
                        $string12 = "Running elusiveMice 'BEACON_RDLL_GENERATE" nocase ascii wide

    condition:
        any of them
}