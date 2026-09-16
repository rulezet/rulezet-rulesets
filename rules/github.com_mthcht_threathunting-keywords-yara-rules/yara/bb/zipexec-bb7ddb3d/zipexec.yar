rule ZipExec
{
    meta:
        description = "Detection patterns for the tool 'ZipExec' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ZipExec"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/ZipExec -" nocase ascii wide
                        $string2 = /\/ZipExec\.git/ nocase ascii wide
                        $string3 = "/ZipExec@latest" nocase ascii wide
                        $string4 = /\\ZipExec\s\-/ nocase ascii wide
                        $string5 = /\\ZipExec\.exe/ nocase ascii wide
                        $string6 = /\\ZipExec\.go/ nocase ascii wide
                        $string7 = "b206d36ab4eb52419e27ca315cc9151e86eb31513ab6aa28fe8879141ef746bb" nocase ascii wide
                        $string8 = /build\sZipExec\.go/ nocase ascii wide
                        $string9 = /calc\.zip\s\/pass\:xOVTzio/ nocase ascii wide
                        $string10 = "Tylous/ZipExec" nocase ascii wide
                        $string11 = "ZipExec/Cryptor" nocase ascii wide
                        $string12 = "ZipExec/Loader" nocase ascii wide

    condition:
        any of them
}