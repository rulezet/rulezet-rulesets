rule OperaPassView
{
    meta:
        description = "Detection patterns for the tool 'OperaPassView' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "OperaPassView"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/operapassview\.zip/ nocase ascii wide
                        $string2 = /\\OperaPassView\.chm/ nocase ascii wide
                        $string3 = /\\operapassview\.zip/ nocase ascii wide
                        $string4 = /\\OperaPassView_lng\.ini/ nocase ascii wide
                        $string5 = ">OperaPassView<" nocase ascii wide
                        $string6 = "8e4b218bdbd8e098fff749fe5e5bbf00275d21f398b34216a573224e192094b8" nocase ascii wide
                        $string7 = "941e4b332bf0cbb3573b3936b114a41f1d416bb96ba13c333f6269074a8ae7f6" nocase ascii wide
                        $string8 = /OperaPassView\.exe/ nocase ascii wide

    condition:
        any of them
}