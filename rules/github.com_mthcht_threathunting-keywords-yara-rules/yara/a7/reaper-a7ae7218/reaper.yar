rule reaper
{
    meta:
        description = "Detection patterns for the tool 'reaper' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "reaper"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/Reaper\.git/ nocase ascii wide
                        $string2 = /\/Reaper\/Reaper\.cpp/ nocase ascii wide
                        $string3 = /\/ReaperX64\.zip/ nocase ascii wide
                        $string4 = /\\Reaper\\Reaper\.cpp/ nocase ascii wide
                        $string5 = /\\Reaper\-main\\.{0,1000}\.sys/ nocase ascii wide
                        $string6 = /\\Temp\\Reaper\.exe/ nocase ascii wide
                        $string7 = "30f7ba049eab00673ae6b247199ec4f6af533d9ba46482159668fd23f484bdc6" nocase ascii wide
                        $string8 = "526f652d4d9e20a19374817eac75b914b75f3bfaecc16b65f979e5758ea62476" nocase ascii wide
                        $string9 = "c725919e6357126d512c638f993cf572112f323da359645e4088f789eb4c7b8c" nocase ascii wide
                        $string10 = "CB561720-0175-49D9-A114-FE3489C53661" nocase ascii wide
                        $string11 = /github\.com\/.{0,1000}Reaper\.exe/ nocase ascii wide
                        $string12 = "MrEmpy/Reaper" nocase ascii wide
                        $string13 = /Reaper\.exe\skp\s/ nocase ascii wide
                        $string14 = /Reaper\.exe\ssp\s/ nocase ascii wide
                        $string15 = /Reaper\-main\.zip/ nocase ascii wide

    condition:
        any of them
}