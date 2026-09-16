rule Adzok
{
    meta:
        description = "Detection patterns for the tool 'Adzok' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Adzok"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\\Adzok_Open_v.{0,1000}\.jar/ nocase ascii wide
                        $string2 = "88147650f66ab1b4ec3d2a97ef8083ebd78cfdde63f7a5bad73b2d4e9e48a365" nocase ascii wide
                        $string3 = /http\:\/\/adzok\.net\/downloadfree\.php/ nocase ascii wide
                        $string4 = /http\:\/\/sourceforge\.net\/projects\/adzok\/files\/Adzok_Open_v1\.0\.0\.2\.jar\/download/ nocase ascii wide

    condition:
        any of them
}