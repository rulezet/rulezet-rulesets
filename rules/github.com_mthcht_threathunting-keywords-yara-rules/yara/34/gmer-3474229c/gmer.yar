rule gmer
{
    meta:
        description = "Detection patterns for the tool 'gmer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "gmer"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/gmer\.exe/ nocase ascii wide
                        $string2 = /\/gmer64\.sys/
                        $string3 = /\\gmer\.exe/ nocase ascii wide
                        $string4 = /\\gmer64\.pdb/ nocase ascii wide
                        $string5 = /\\gmer64\.sys/ nocase ascii wide
                        $string6 = /\\Release\\gmer\.pdb/ nocase ascii wide
                        $string7 = /\>GMER\sDriver\shttp\:\/\/www\.gmer\.net\</ nocase ascii wide
                        $string8 = "18c909a2b8c5e16821d6ef908f56881aa0ecceeaccb5fa1e54995935fcfd12f7" nocase ascii wide
                        $string9 = "de3abde117d7eacbb638bc7d0151f929cf80a4bb5e5beb1e390839e96fc6722a" nocase ascii wide
                        $string10 = "e8a3e804a96c716a3e9b69195db6ffb0d33e2433af871e4d4e1eab3097237173" nocase ascii wide
                        $string11 = "e8a3e804a96c716a3e9b69195db6ffb0d33e2433af871e4d4e1eab3097237173" nocase ascii wide
                        $string12 = /http\:\/\/www\.gmer\.net\/\#files/ nocase ascii wide
                        $string13 = /http\:\/\/www2\.gmer\.net\/download/ nocase ascii wide
                        $string14 = /http\:\/\/www2\.gmer\.net\/gmer\.zip/ nocase ascii wide

    condition:
        any of them
}