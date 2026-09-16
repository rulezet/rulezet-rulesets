rule rule_WhatBreach_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'WhatBreach' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WhatBreach"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_WhatBreach_offensive_tool_keyword = "WhatBreach" nocase ascii wide

    condition:
        any of them
}