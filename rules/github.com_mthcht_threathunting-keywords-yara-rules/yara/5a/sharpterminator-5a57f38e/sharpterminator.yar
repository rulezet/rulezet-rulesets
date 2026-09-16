rule SharpTerminator
{
    meta:
        description = "Detection patterns for the tool 'SharpTerminator' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpTerminator"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\.exe.{0,1000}\\Terminator\.sys/ nocase ascii wide
                        $string2 = "/SharpTerminator/" nocase ascii wide
                        $string3 = /\/terminate\/Terminator\.sys/ nocase ascii wide
                        $string4 = /\\SharpTerminator\.csproj/ nocase ascii wide
                        $string5 = /http.{0,1000}\:\/\/.{0,1000}\/Terminator\.sys/ nocase ascii wide
                        $string6 = "mertdas/SharpTerminator" nocase ascii wide
                        $string7 = /sc\screate\sTerminator\s.{0,1000}\.sys/ nocase ascii wide
                        $string8 = /SharpTerminator\.exe/ nocase ascii wide
                        $string9 = /SharpTerminator\.git/ nocase ascii wide
                        $string10 = /SharpTerminator\.sln/ nocase ascii wide
                        $string11 = /SharpTerminator\-main\.zip/ nocase ascii wide

    condition:
        any of them
}