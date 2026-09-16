rule rule__1ty_me_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool '1ty.me' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "1ty.me"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1__1ty_me_greyware_tool_keyword = /https\:\/\/1ty\.me\// nocase ascii wide
                        $string2__1ty_me_greyware_tool_keyword = /https\:\/\/1ty\.me\/\?mode\=ajax\&cmd\=create_note/ nocase ascii wide

    condition:
        any of them
}