rule rule_EncryptedZIP_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'EncryptedZIP' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EncryptedZIP"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_EncryptedZIP_offensive_tool_keyword = /\sdecrypt\s.{0,1000}\.aes\.zip/ nocase ascii wide
                        $string2_EncryptedZIP_offensive_tool_keyword = /EncryptedZIP\.csproj/ nocase ascii wide
                        $string3_EncryptedZIP_offensive_tool_keyword = /EncryptedZIP\.exe/ nocase ascii wide
                        $string4_EncryptedZIP_offensive_tool_keyword = "master/EncryptedZIP" nocase ascii wide
                        $string5_EncryptedZIP_offensive_tool_keyword = /Output\.aes\.zip/ nocase ascii wide

    condition:
        any of them
}