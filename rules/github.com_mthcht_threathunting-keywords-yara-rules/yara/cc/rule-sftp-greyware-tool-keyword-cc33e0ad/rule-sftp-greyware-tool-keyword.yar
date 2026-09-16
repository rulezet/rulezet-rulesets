rule rule_sftp_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'sftp' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sftp"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_sftp_greyware_tool_keyword = /\/sftp\s.{0,1000}\@.{0,1000}\:.{0,1000}\s/
                        $string2_sftp_greyware_tool_keyword = /\/sftp\s.{0,1000}get.{0,1000}\.wallet/
                        $string3_sftp_greyware_tool_keyword = /\/sftp\s.{0,1000}put.{0,1000}\.tar\.gz/

    condition:
        any of them
}