rule rule_pyinstaller_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'pyinstaller' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pyinstaller"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_pyinstaller_greyware_tool_keyword = "/pyinstaller/"
                        $string2_pyinstaller_greyware_tool_keyword = "import PyInstaller" nocase ascii wide
                        $string3_pyinstaller_greyware_tool_keyword = "install pyinstaller" nocase ascii wide
                        $string4_pyinstaller_greyware_tool_keyword = /pyinstaller\s.{0,1000}\.py/ nocase ascii wide
                        $string5_pyinstaller_greyware_tool_keyword = /pyinstaller.{0,1000}\s\-\-onefile\s\-\-add\-data\s/ nocase ascii wide
                        $string6_pyinstaller_greyware_tool_keyword = /pyinstaller\.exe/ nocase ascii wide
                        $string7_pyinstaller_greyware_tool_keyword = "pyinstaller/tarball" nocase ascii wide
                        $string8_pyinstaller_greyware_tool_keyword = /pyinstaller\-script\.py/ nocase ascii wide

    condition:
        any of them
}