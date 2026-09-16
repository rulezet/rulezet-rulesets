rule sftp
{
    meta:
        description = "Detection patterns for the tool 'sftp' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sftp"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\/sftp\s.{0,1000}\@.{0,1000}\:.{0,1000}\s/
                        $string2 = /\/sftp\s.{0,1000}get.{0,1000}\.wallet/
                        $string3 = /\/sftp\s.{0,1000}put.{0,1000}\.tar\.gz/

    condition:
        any of them
}