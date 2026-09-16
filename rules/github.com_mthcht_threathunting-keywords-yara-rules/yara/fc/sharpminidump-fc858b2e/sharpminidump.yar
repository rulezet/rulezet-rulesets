rule SharpMiniDump
{
    meta:
        description = "Detection patterns for the tool 'SharpMiniDump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpMiniDump"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/SharpMiniDump\.git/ nocase ascii wide
                        $string2 = /\\SharpMiniDump\-master/ nocase ascii wide
                        $string3 = /\\Temp\\dumpert\.dmp/ nocase ascii wide
                        $string4 = ">SharpMiniDump<" nocase ascii wide
                        $string5 = "34cfee78a17d917fabf8d9a2b48fb55f8231c0b24a5f4197615d140d18eb9b2d" nocase ascii wide
                        $string6 = "40a2c9d397f398d5faa631d6c6070174807e39962a22be143e35b7497b5c6bd7" nocase ascii wide
                        $string7 = "6FFCCF81-6C3C-4D3F-B15F-35A86D0B497F" nocase ascii wide
                        $string8 = "b4rtik/SharpMiniDump" nocase ascii wide
                        $string9 = "f988bd7635bc12561e00eeb4aff027bd8014dc9b13600c8e8fb597ac9de5c3cf" nocase ascii wide
                        $string10 = /SharpMiniDump\.exe/ nocase ascii wide

    condition:
        any of them
}