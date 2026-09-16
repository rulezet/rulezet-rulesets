rule EncryptedZIP
{
    meta:
        description = "Detection patterns for the tool 'EncryptedZIP' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EncryptedZIP"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sdecrypt\s.{0,1000}\.aes\.zip/ nocase ascii wide
                        $string2 = /EncryptedZIP\.csproj/ nocase ascii wide
                        $string3 = /EncryptedZIP\.exe/ nocase ascii wide
                        $string4 = "master/EncryptedZIP" nocase ascii wide
                        $string5 = /Output\.aes\.zip/ nocase ascii wide

    condition:
        any of them
}