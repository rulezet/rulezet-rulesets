rule HijackHunter
{
    meta:
        description = "Detection patterns for the tool 'HijackHunter' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "HijackHunter"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/HijackHunter/" nocase ascii wide
                        $string2 = /\\HijackHunter\\/ nocase ascii wide
                        $string3 = /dll.{0,1000}\s\[HIJACKABLE\]/ nocase ascii wide
                        $string4 = /HijackHunter\.csproj/ nocase ascii wide
                        $string5 = /HijackHunter\.exe/ nocase ascii wide
                        $string6 = "hijackProgDirMissingDll" nocase ascii wide

    condition:
        any of them
}