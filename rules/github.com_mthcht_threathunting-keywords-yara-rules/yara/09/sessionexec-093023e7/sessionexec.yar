rule SessionExec
{
    meta:
        description = "Detection patterns for the tool 'SessionExec' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SessionExec"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/SessionExec\.exe/ nocase ascii wide
                        $string2 = /\\SessionExec\.exe/ nocase ascii wide
                        $string3 = "9065655de782c08c41aa0fe11503e92e455fdf4b1a590101221aeb73f8db98e9" nocase ascii wide
                        $string4 = "function Invoke-SessionExec" nocase ascii wide
                        $string5 = "Invoke-SessionExec " nocase ascii wide
                        $string6 = /Invoke\-SessionExec\.ps1/ nocase ascii wide

    condition:
        any of them
}