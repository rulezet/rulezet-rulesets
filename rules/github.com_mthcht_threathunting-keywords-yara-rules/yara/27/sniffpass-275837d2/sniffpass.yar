rule SniffPass
{
    meta:
        description = "Detection patterns for the tool 'SniffPass' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SniffPass"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/password_sniffer\.html/ nocase ascii wide
                        $string2 = "/sniffpass-x64" nocase ascii wide
                        $string3 = /\\SniffPass\.chm/ nocase ascii wide
                        $string4 = /\\SniffPass\.pdb/ nocase ascii wide
                        $string5 = /\\sniffpass\-x64/ nocase ascii wide
                        $string6 = ">Password Sniffer<" nocase ascii wide
                        $string7 = ">SniffPass<" nocase ascii wide
                        $string8 = "1df8e073ca89d026578464b0da9748194ef62c826dea4af9848ef23b3ddf1785" nocase ascii wide
                        $string9 = "c92580318be4effdb37aa67145748826f6a9e285bc2426410dc280e61e3c7620" nocase ascii wide
                        $string10 = /http\:\/\/www\.nirsoft\.net\/password_test/ nocase ascii wide
                        $string11 = "PacketSnifferClass1" nocase ascii wide
                        $string12 = /SniffPass\.exe/ nocase ascii wide
                        $string13 = /sniffpass\-x64\.zip/ nocase ascii wide
                        $string14 = /Software\\NirSoft\\SniffPass/ nocase ascii wide

    condition:
        any of them
}