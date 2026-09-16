rule powerextract
{
    meta:
        description = "Detection patterns for the tool 'powerextract' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "powerextract"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\-PathToDMP\s.{0,1000}\.dmp/ nocase ascii wide
                        $string2 = /\/PowerExtract\.git/ nocase ascii wide
                        $string3 = /\/PowerExtract\.git/ nocase ascii wide
                        $string4 = "Get-KIWI_KERBEROS_LOGON_SESSION" nocase ascii wide
                        $string5 = "Invoke-PowerExtract" nocase ascii wide
                        $string6 = /PowerExtract\-main\.zip/ nocase ascii wide
                        $string7 = "powerseb/PowerExtract" nocase ascii wide
                        $string8 = "powerseb/PowerExtract" nocase ascii wide

    condition:
        any of them
}