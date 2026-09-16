rule rule_PPLmedic_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'PPLmedic' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PPLmedic"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_PPLmedic_offensive_tool_keyword = /\sPPLmedic\.exe/ nocase ascii wide
                        $string2_PPLmedic_offensive_tool_keyword = /\/PPLmedic\.exe/ nocase ascii wide
                        $string3_PPLmedic_offensive_tool_keyword = /\/PPLmedic\.git/ nocase ascii wide
                        $string4_PPLmedic_offensive_tool_keyword = /\[\+\]\sPayload\sDLL\ssuccessfully\sloaded\safter/ nocase ascii wide
                        $string5_PPLmedic_offensive_tool_keyword = /\\\\PPLmedic\\\\ntstuff/ nocase ascii wide
                        $string6_PPLmedic_offensive_tool_keyword = /\\ExploitElevate\.cpp/ nocase ascii wide
                        $string7_PPLmedic_offensive_tool_keyword = /\\PPLmedic\.cpp/ nocase ascii wide
                        $string8_PPLmedic_offensive_tool_keyword = /\\PPLmedic\.exe/ nocase ascii wide
                        $string9_PPLmedic_offensive_tool_keyword = /\\PPLmedic\\PPLmedic/ nocase ascii wide
                        $string10_PPLmedic_offensive_tool_keyword = /\\Temp\\csrss\.dmp/ nocase ascii wide
                        $string11_PPLmedic_offensive_tool_keyword = /\\Temp\\lsass\.dmp/ nocase ascii wide
                        $string12_PPLmedic_offensive_tool_keyword = "29CBBC24-363F-42D7-B018-5EF068BA8777" nocase ascii wide
                        $string13_PPLmedic_offensive_tool_keyword = "4d2f66539f067f631db31039ec81707028bb37efcd2ebbf86a1a920d60d75263" nocase ascii wide
                        $string14_PPLmedic_offensive_tool_keyword = "ac49d2041cd57b1efba672c3305b621ebb265380010b8951cda01c055a7e1e64" nocase ascii wide
                        $string15_PPLmedic_offensive_tool_keyword = "db03400af112a7969ba2d68288b9dc908b2d234d62184fd5f01079749c4bf09e" nocase ascii wide
                        $string16_PPLmedic_offensive_tool_keyword = "F00A3B5F-D9A9-4582-BBCE-FD10EFBF0C17" nocase ascii wide
                        $string17_PPLmedic_offensive_tool_keyword = "fa06c45e4522706565bea7e2532ba67cf2cad3e57e38157c09e46445c1dd100a" nocase ascii wide
                        $string18_PPLmedic_offensive_tool_keyword = "itm4n/PPLmedic" nocase ascii wide
                        $string19_PPLmedic_offensive_tool_keyword = /PPLmedicDll\.def/ nocase ascii wide
                        $string20_PPLmedic_offensive_tool_keyword = /PPLmedicDll\.dll/ nocase ascii wide
                        $string21_PPLmedic_offensive_tool_keyword = /WaaSMedicPayload\.dll/ nocase ascii wide

    condition:
        any of them
}