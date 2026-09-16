rule Taskmgr
{
    meta:
        description = "Detection patterns for the tool 'Taskmgr' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Taskmgr"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\<Data\sName\=\'PipeName\'\>\\lsass\<\/Data\>\<Data\sName\=\'Image\'\>C\:\\Windows\\System32\\Taskmgr\.exe\<\/Data\>/ nocase ascii wide

    condition:
        any of them
}