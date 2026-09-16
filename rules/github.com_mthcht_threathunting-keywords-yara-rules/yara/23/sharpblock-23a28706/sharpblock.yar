rule SharpBlock
{
    meta:
        description = "Detection patterns for the tool 'SharpBlock' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpBlock"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\-d\s.{0,1000}Active\sProtection\sDLL\sfor\sSylantStrike/ nocase ascii wide
                        $string2 = " --disable-bypass-amsi" nocase ascii wide
                        $string3 = " --disable-bypass-cmdline" nocase ascii wide
                        $string4 = " --disable-bypass-etw" nocase ascii wide
                        $string5 = "/SharpSploit/" nocase ascii wide
                        $string6 = /\\\\\.\\pipe\\mimi/ nocase ascii wide
                        $string7 = "execute-assembly SharpBlock" nocase ascii wide
                        $string8 = "SharpBlock -" nocase ascii wide
                        $string9 = /SharpBlock\.csproj/ nocase ascii wide
                        $string10 = /SharpBlock\.exe/ nocase ascii wide
                        $string11 = /SharpBlock\.sln/ nocase ascii wide

    condition:
        any of them
}