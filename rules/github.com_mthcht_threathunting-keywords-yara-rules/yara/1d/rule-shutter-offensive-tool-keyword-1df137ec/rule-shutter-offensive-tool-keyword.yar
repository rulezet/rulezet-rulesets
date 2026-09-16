rule rule_shutter_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'shutter' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "shutter"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_shutter_offensive_tool_keyword = /\\add\-filters\-defender\-crowdstrike\.json/ nocase ascii wide
                        $string2_shutter_offensive_tool_keyword = /\\shutter\-main\.zip/ nocase ascii wide
                        $string3_shutter_offensive_tool_keyword = /\\x64\\Debug\\Appblock\.exe/ nocase ascii wide
                        $string4_shutter_offensive_tool_keyword = "2164E6D9-6023-4932-A08F-7A5C15E2CA0B" nocase ascii wide
                        $string5_shutter_offensive_tool_keyword = "326D0AB1-CF2F-4A9B-B612-04B62D4EBA89" nocase ascii wide
                        $string6_shutter_offensive_tool_keyword = /appblock.{0,1000}wfpsessionmanager\.obj/ nocase ascii wide
                        $string7_shutter_offensive_tool_keyword = /Appblock\.exe\s\-\-add/ nocase ascii wide
                        $string8_shutter_offensive_tool_keyword = /Appblock\.exe\s\-\-list/ nocase ascii wide
                        $string9_shutter_offensive_tool_keyword = "B52E2D10-A94A-4605-914A-2DCEF6A757EF" nocase ascii wide
                        $string10_shutter_offensive_tool_keyword = "dsnezhkov/shutter" nocase ascii wide
                        $string11_shutter_offensive_tool_keyword = "e11cbe43-b8bc-4042-a4a5-c8e960925c83" nocase ascii wide
                        $string12_shutter_offensive_tool_keyword = "F3FEBDE7-FBC8-48EC-8F24-5F33B8ACFB2A" nocase ascii wide
                        $string13_shutter_offensive_tool_keyword = /\-\-filter\=add\-filters\-defender\-crowdstrike\.json/ nocase ascii wide

    condition:
        any of them
}