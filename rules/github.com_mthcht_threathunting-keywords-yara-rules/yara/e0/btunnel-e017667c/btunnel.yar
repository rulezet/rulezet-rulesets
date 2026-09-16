rule btunnel
{
    meta:
        description = "Detection patterns for the tool 'btunnel' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "btunnel"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\/\.btunnel\./
                        $string2 = /\/btunnel\.exe/ nocase ascii wide
                        $string3 = /\/btunnel\.log/
                        $string4 = /\\\.btunnel\./ nocase ascii wide
                        $string5 = /\\bored\-tunnel\-client/ nocase ascii wide
                        $string6 = /\\btunnel\.exe/ nocase ascii wide
                        $string7 = /\\btunnel\.log/ nocase ascii wide
                        $string8 = "60e8a9e19b34ca6d9f1847504b7689b3f46b029ab07b4d13c6ccde026d78a0a4" nocase ascii wide
                        $string9 = "af19236f06140b33ac3c78ae743627ba34dcd89be6d5c8dd22cac7f6eae19774" nocase ascii wide
                        $string10 = /api\.btunnel\.in/ nocase ascii wide
                        $string11 = /bored\-tunnel\-client_Windows_x86_64\./ nocase ascii wide
                        $string12 = "btunnel domain " nocase ascii wide
                        $string13 = "btunnel file " nocase ascii wide
                        $string14 = "btunnel http" nocase ascii wide
                        $string15 = "btunnel tcp --" nocase ascii wide
                        $string16 = "btunnel tcp" nocase ascii wide
                        $string17 = /btunnel\.exe\shttp/ nocase ascii wide
                        $string18 = "eb1395952e6eb92d4f9a2babb56d29ef384d683387c6a990e79d5fe4ba86040f" nocase ascii wide
                        $string19 = /http\:\/\/tcp\.btunnel\.in/ nocase ascii wide
                        $string20 = /https\:\/\/.{0,1000}\.btunnel\.co\.in/ nocase ascii wide
                        $string21 = /https\:\/\/.{0,1000}\.btunnel\.co\.in/ nocase ascii wide
                        $string22 = /https\:\/\/www\.btunnel\.in\/downloads/ nocase ascii wide

    condition:
        any of them
}