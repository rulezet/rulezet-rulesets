rule rule_ZipExec_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ZipExec' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ZipExec"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_ZipExec_offensive_tool_keyword = "/ZipExec -" nocase ascii wide
                        $string2_ZipExec_offensive_tool_keyword = /\/ZipExec\.git/ nocase ascii wide
                        $string3_ZipExec_offensive_tool_keyword = "/ZipExec@latest" nocase ascii wide
                        $string4_ZipExec_offensive_tool_keyword = /\\ZipExec\s\-/ nocase ascii wide
                        $string5_ZipExec_offensive_tool_keyword = /\\ZipExec\.exe/ nocase ascii wide
                        $string6_ZipExec_offensive_tool_keyword = /\\ZipExec\.go/ nocase ascii wide
                        $string7_ZipExec_offensive_tool_keyword = "b206d36ab4eb52419e27ca315cc9151e86eb31513ab6aa28fe8879141ef746bb" nocase ascii wide
                        $string8_ZipExec_offensive_tool_keyword = /build\sZipExec\.go/ nocase ascii wide
                        $string9_ZipExec_offensive_tool_keyword = /calc\.zip\s\/pass\:xOVTzio/ nocase ascii wide
                        $string10_ZipExec_offensive_tool_keyword = "Tylous/ZipExec" nocase ascii wide
                        $string11_ZipExec_offensive_tool_keyword = "ZipExec/Cryptor" nocase ascii wide
                        $string12_ZipExec_offensive_tool_keyword = "ZipExec/Loader" nocase ascii wide

    condition:
        any of them
}