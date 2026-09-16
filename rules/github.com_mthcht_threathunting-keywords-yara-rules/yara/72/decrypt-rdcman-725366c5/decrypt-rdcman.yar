rule Decrypt_RDCMan
{
    meta:
        description = "Detection patterns for the tool 'Decrypt-RDCMan' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Decrypt-RDCMan"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sDecrypt\-RDCMan\.ps1/ nocase ascii wide
                        $string2 = /\/Decrypt\-RDCMan\.ps1/ nocase ascii wide
                        $string3 = /\\Decrypt\-RDCMan\.ps1/ nocase ascii wide
                        $string4 = "2e7451bba0392fb9d687c8cf6d7b99a7983742542ac0217d11f899d2d7bad07b" nocase ascii wide
                        $string5 = "Decrypt-RDCMan -FilePath" nocase ascii wide
                        $string6 = "function Decrypt-RDCMan" nocase ascii wide
                        $string7 = /Get\-Content\s\\"\$env\:LOCALAPPDATA\\microsoft\\remote\sdesktop\sconnection\smanager\\rdcman\.settings/ nocase ascii wide

    condition:
        any of them
}