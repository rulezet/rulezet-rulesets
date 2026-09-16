rule shutter
{
    meta:
        description = "Detection patterns for the tool 'shutter' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "shutter"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\\add\-filters\-defender\-crowdstrike\.json/ nocase ascii wide
                        $string2 = /\\shutter\-main\.zip/ nocase ascii wide
                        $string3 = /\\x64\\Debug\\Appblock\.exe/ nocase ascii wide
                        $string4 = "2164E6D9-6023-4932-A08F-7A5C15E2CA0B" nocase ascii wide
                        $string5 = "326D0AB1-CF2F-4A9B-B612-04B62D4EBA89" nocase ascii wide
                        $string6 = /appblock.{0,1000}wfpsessionmanager\.obj/ nocase ascii wide
                        $string7 = /Appblock\.exe\s\-\-add/ nocase ascii wide
                        $string8 = /Appblock\.exe\s\-\-list/ nocase ascii wide
                        $string9 = "B52E2D10-A94A-4605-914A-2DCEF6A757EF" nocase ascii wide
                        $string10 = "dsnezhkov/shutter" nocase ascii wide
                        $string11 = "e11cbe43-b8bc-4042-a4a5-c8e960925c83" nocase ascii wide
                        $string12 = "F3FEBDE7-FBC8-48EC-8F24-5F33B8ACFB2A" nocase ascii wide
                        $string13 = /\-\-filter\=add\-filters\-defender\-crowdstrike\.json/ nocase ascii wide

    condition:
        any of them
}