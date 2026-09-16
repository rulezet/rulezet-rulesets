rule easyupload_io
{
    meta:
        description = "Detection patterns for the tool 'easyupload.io' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "easyupload.io"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /https\:\/\/easyupload\.io\// nocase ascii wide
                        $string2 = /https\:\/\/easyupload\.io\/action\.php/ nocase ascii wide
                        $string3 = /https\:\/\/easyupload\.io\/cdn\-cgi\/rum/ nocase ascii wide
                        $string4 = /upload4\.easyupload\.io/ nocase ascii wide

    condition:
        any of them
}