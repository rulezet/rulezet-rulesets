rule py2exe
{
    meta:
        description = "Detection patterns for the tool 'py2exe' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "py2exe"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = " py2exe" nocase ascii wide
                        $string2 = "/py2exe/" nocase ascii wide
                        $string3 = /\\py2exe/ nocase ascii wide
                        $string4 = "py2exe " nocase ascii wide
                        $string5 = /py2exe.{0,1000}\.exe\s/ nocase ascii wide
                        $string6 = /py2exe.{0,1000}\.msi\s/ nocase ascii wide
                        $string7 = /py2exe.{0,1000}\.py/ nocase ascii wide
                        $string8 = /py2exe\-.{0,1000}\.tar\.gz/ nocase ascii wide
                        $string9 = /py2exe\-.{0,1000}\.whl/ nocase ascii wide
                        $string10 = /py2exe\.build_exe/ nocase ascii wide
                        $string11 = /py2exe\.freeze/ nocase ascii wide
                        $string12 = /py2exe\.git/ nocase ascii wide
                        $string13 = /py2exe_setuptools\.py/ nocase ascii wide
                        $string14 = /py2exe\-master\.zip/ nocase ascii wide

    condition:
        any of them
}