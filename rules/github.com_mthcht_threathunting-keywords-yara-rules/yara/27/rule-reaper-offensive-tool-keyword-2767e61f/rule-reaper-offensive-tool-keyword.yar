rule rule_reaper_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'reaper' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "reaper"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_reaper_offensive_tool_keyword = /\/Reaper\.git/ nocase ascii wide
                        $string2_reaper_offensive_tool_keyword = /\/Reaper\/Reaper\.cpp/ nocase ascii wide
                        $string3_reaper_offensive_tool_keyword = /\/ReaperX64\.zip/ nocase ascii wide
                        $string4_reaper_offensive_tool_keyword = /\\Reaper\\Reaper\.cpp/ nocase ascii wide
                        $string5_reaper_offensive_tool_keyword = /\\Reaper\-main\\.{0,1000}\.sys/ nocase ascii wide
                        $string6_reaper_offensive_tool_keyword = /\\Temp\\Reaper\.exe/ nocase ascii wide
                        $string7_reaper_offensive_tool_keyword = "30f7ba049eab00673ae6b247199ec4f6af533d9ba46482159668fd23f484bdc6" nocase ascii wide
                        $string8_reaper_offensive_tool_keyword = "526f652d4d9e20a19374817eac75b914b75f3bfaecc16b65f979e5758ea62476" nocase ascii wide
                        $string9_reaper_offensive_tool_keyword = "c725919e6357126d512c638f993cf572112f323da359645e4088f789eb4c7b8c" nocase ascii wide
                        $string10_reaper_offensive_tool_keyword = "CB561720-0175-49D9-A114-FE3489C53661" nocase ascii wide
                        $string11_reaper_offensive_tool_keyword = /github\.com\/.{0,1000}Reaper\.exe/ nocase ascii wide
                        $string12_reaper_offensive_tool_keyword = "MrEmpy/Reaper" nocase ascii wide
                        $string13_reaper_offensive_tool_keyword = /Reaper\.exe\skp\s/ nocase ascii wide
                        $string14_reaper_offensive_tool_keyword = /Reaper\.exe\ssp\s/ nocase ascii wide
                        $string15_reaper_offensive_tool_keyword = /Reaper\-main\.zip/ nocase ascii wide

    condition:
        any of them
}