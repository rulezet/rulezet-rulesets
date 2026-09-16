rule smb_reverse_shell
{
    meta:
        description = "Detection patterns for the tool 'smb-reverse-shell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "smb-reverse-shell"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/smb-reverse-shell" nocase ascii wide
                        $string2 = /invoke.{0,1000}\s\-Action\scommand\s\-Execute\s.{0,1000}\s\-Session/ nocase ascii wide
                        $string3 = "Invoke-SmbObey " nocase ascii wide
                        $string4 = /Invoke\-SmbObey\./ nocase ascii wide
                        $string5 = "Invoke-SmbOrder " nocase ascii wide
                        $string6 = /Invoke\-SmbOrder\./ nocase ascii wide
                        $string7 = /smb\-reverse\-shell\.git/ nocase ascii wide
                        $string8 = "smb-reverse-shell-main" nocase ascii wide

    condition:
        any of them
}