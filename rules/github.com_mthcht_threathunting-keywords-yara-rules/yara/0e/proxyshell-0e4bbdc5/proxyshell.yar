rule ProxyShell
{
    meta:
        description = "Detection patterns for the tool 'ProxyShell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ProxyShell"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /New\-MailBoxExportRequest\s\-Mailbox\s.{0,1000}\@.{0,1000}\s\-FilePath\s.{0,1000}\.aspx/ nocase ascii wide
                        $string2 = /Set\-OabVirtualDirectory\s\-ExternalUrl\s\'http.{0,1000}\:\/\/.{0,1000}function\sPage_Load\(\)\{.{0,1000}\}\<\/script\>/ nocase ascii wide

    condition:
        any of them
}