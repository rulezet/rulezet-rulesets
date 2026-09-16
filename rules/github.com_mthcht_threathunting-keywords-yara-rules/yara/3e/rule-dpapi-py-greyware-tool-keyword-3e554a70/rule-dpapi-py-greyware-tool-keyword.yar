rule rule_dpapi_py_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'dpapi.py' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dpapi.py"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_dpapi_py_greyware_tool_keyword = /dpapi\.py\sbackupkeys\s\-t\s.{0,1000}\/.{0,1000}\@/ nocase ascii wide

    condition:
        any of them
}