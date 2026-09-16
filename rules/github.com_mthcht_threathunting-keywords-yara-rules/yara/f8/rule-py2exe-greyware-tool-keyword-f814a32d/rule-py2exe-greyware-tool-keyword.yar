rule rule_py2exe_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'py2exe' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "py2exe"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_py2exe_greyware_tool_keyword = " py2exe" nocase ascii wide
                        $string2_py2exe_greyware_tool_keyword = "/py2exe/" nocase ascii wide
                        $string3_py2exe_greyware_tool_keyword = /\\py2exe/ nocase ascii wide
                        $string4_py2exe_greyware_tool_keyword = "py2exe " nocase ascii wide
                        $string5_py2exe_greyware_tool_keyword = /py2exe.{0,1000}\.exe\s/ nocase ascii wide
                        $string6_py2exe_greyware_tool_keyword = /py2exe.{0,1000}\.msi\s/ nocase ascii wide
                        $string7_py2exe_greyware_tool_keyword = /py2exe.{0,1000}\.py/ nocase ascii wide
                        $string8_py2exe_greyware_tool_keyword = /py2exe\-.{0,1000}\.tar\.gz/ nocase ascii wide
                        $string9_py2exe_greyware_tool_keyword = /py2exe\-.{0,1000}\.whl/ nocase ascii wide
                        $string10_py2exe_greyware_tool_keyword = /py2exe\.build_exe/ nocase ascii wide
                        $string11_py2exe_greyware_tool_keyword = /py2exe\.freeze/ nocase ascii wide
                        $string12_py2exe_greyware_tool_keyword = /py2exe\.git/ nocase ascii wide
                        $string13_py2exe_greyware_tool_keyword = /py2exe_setuptools\.py/ nocase ascii wide
                        $string14_py2exe_greyware_tool_keyword = /py2exe\-master\.zip/ nocase ascii wide

    condition:
        any of them
}