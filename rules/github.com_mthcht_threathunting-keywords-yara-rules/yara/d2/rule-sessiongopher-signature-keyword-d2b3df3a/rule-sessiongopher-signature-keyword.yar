rule rule_SessionGopher_signature_keyword
{
    meta:
        description = "Detection patterns for the tool 'SessionGopher' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SessionGopher"
        rule_category = "signature_keyword"

    strings:
                        $string1_SessionGopher_signature_keyword = /Application\.Hacktool\.SessionGopher/ nocase ascii wide
                        $string2_SessionGopher_signature_keyword = "ddbf3299675ffdd7e3475f8a4848f3ab6cdff8819348c75b9ac4d8fb76569a2c" nocase ascii wide
                        $string3_SessionGopher_signature_keyword = /HackTool\.PS1\.SessionGopher/ nocase ascii wide
                        $string4_SessionGopher_signature_keyword = "HTool-SessionGopher" nocase ascii wide
                        $string5_SessionGopher_signature_keyword = /PowerShell\/HackTool\.SessionGopher/ nocase ascii wide

    condition:
        any of them
}