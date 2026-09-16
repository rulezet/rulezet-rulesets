rule whoami
{
    meta:
        description = "Detection patterns for the tool 'whoami' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "whoami"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = " -exec bypass -nop -c whoami" nocase ascii wide
                        $string2 = "whoami /all" nocase ascii wide
                        $string3 = "whoami /domain" nocase ascii wide
                        $string4 = "whoami /groups" nocase ascii wide
                        $string5 = "whoami /priv" nocase ascii wide
                        $string6 = "whoami" nocase ascii wide
                        $string7 = /whoami\.exe.{0,1000}\s\/groups/ nocase ascii wide

    condition:
        any of them
}