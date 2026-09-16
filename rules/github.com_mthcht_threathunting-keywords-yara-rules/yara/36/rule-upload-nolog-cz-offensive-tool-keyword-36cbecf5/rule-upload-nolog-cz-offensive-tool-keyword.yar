rule rule_upload_nolog_cz_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'upload.nolog.cz' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "upload.nolog.cz"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_upload_nolog_cz_offensive_tool_keyword = /upload\.nolog\.cz/ nocase ascii wide

    condition:
        any of them
}