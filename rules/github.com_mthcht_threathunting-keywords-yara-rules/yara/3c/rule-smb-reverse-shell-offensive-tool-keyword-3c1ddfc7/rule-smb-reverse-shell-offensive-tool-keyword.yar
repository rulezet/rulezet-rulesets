rule rule_smb_reverse_shell_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'smb-reverse-shell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "smb-reverse-shell"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_smb_reverse_shell_offensive_tool_keyword = "/smb-reverse-shell" nocase ascii wide
                        $string2_smb_reverse_shell_offensive_tool_keyword = /invoke.{0,1000}\s\-Action\scommand\s\-Execute\s.{0,1000}\s\-Session/ nocase ascii wide
                        $string3_smb_reverse_shell_offensive_tool_keyword = "Invoke-SmbObey " nocase ascii wide
                        $string4_smb_reverse_shell_offensive_tool_keyword = /Invoke\-SmbObey\./ nocase ascii wide
                        $string5_smb_reverse_shell_offensive_tool_keyword = "Invoke-SmbOrder " nocase ascii wide
                        $string6_smb_reverse_shell_offensive_tool_keyword = /Invoke\-SmbOrder\./ nocase ascii wide
                        $string7_smb_reverse_shell_offensive_tool_keyword = /smb\-reverse\-shell\.git/ nocase ascii wide
                        $string8_smb_reverse_shell_offensive_tool_keyword = "smb-reverse-shell-main" nocase ascii wide

    condition:
        any of them
}