rule rule_Hak5_BashBunny_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Hak5 BashBunny' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Hak5 BashBunny"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Hak5_BashBunny_offensive_tool_keyword = /_USBSTOR\#Disk\&Ven_\&Prod_\&Rev_0000.{0,1000}53f56307\-b6bf\-11d0\-94f2\-00a0c91efb8b/

    condition:
        any of them
}