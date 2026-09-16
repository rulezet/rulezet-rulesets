rule pyinstaller
{
    meta:
        description = "Detection patterns for the tool 'pyinstaller' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pyinstaller"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = "/pyinstaller/"
                        $string2 = "import PyInstaller" nocase ascii wide
                        $string3 = "install pyinstaller" nocase ascii wide
                        $string4 = /pyinstaller\s.{0,1000}\.py/ nocase ascii wide
                        $string5 = /pyinstaller.{0,1000}\s\-\-onefile\s\-\-add\-data\s/ nocase ascii wide
                        $string6 = /pyinstaller\.exe/ nocase ascii wide
                        $string7 = "pyinstaller/tarball" nocase ascii wide
                        $string8 = /pyinstaller\-script\.py/ nocase ascii wide

    condition:
        any of them
}