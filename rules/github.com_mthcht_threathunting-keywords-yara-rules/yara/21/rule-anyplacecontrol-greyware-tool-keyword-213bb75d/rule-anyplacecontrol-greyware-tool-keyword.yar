rule rule_AnyplaceControl_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'AnyplaceControl' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AnyplaceControl"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_AnyplaceControl_greyware_tool_keyword = /\/anyplace\-control\/data2\/.{0,1000}\.exe/ nocase ascii wide
                        $string2_AnyplaceControl_greyware_tool_keyword = /\\Anyplace\sControl\s\-\sAdmin\.lnk/ nocase ascii wide
                        $string3_AnyplaceControl_greyware_tool_keyword = /\\Anyplace\sControl\\/ nocase ascii wide
                        $string4_AnyplaceControl_greyware_tool_keyword = /\\anyplace\-control\.ini/ nocase ascii wide
                        $string5_AnyplaceControl_greyware_tool_keyword = /\\AppData\\Local\\Temp\\.{0,1000}\\zmstage\.exe/ nocase ascii wide
                        $string6_AnyplaceControl_greyware_tool_keyword = /\\AppData\\Roaming\\Anyplace\sControl/ nocase ascii wide
                        $string7_AnyplaceControl_greyware_tool_keyword = /\\Program\sFiles\s\(x86\)\\Anyplace\sControl/ nocase ascii wide
                        $string8_AnyplaceControl_greyware_tool_keyword = /\\ProgramData\\Anyplace\sControl\s/ nocase ascii wide
                        $string9_AnyplaceControl_greyware_tool_keyword = ">Anyplace Control Software<" nocase ascii wide
                        $string10_AnyplaceControl_greyware_tool_keyword = "a2fa034d006bdbc3ee2a15e55eb647f8097355c288a858da1e309fe8ac1cf0a3" nocase ascii wide
                        $string11_AnyplaceControl_greyware_tool_keyword = /AnyplaceControlInstall\.exe/ nocase ascii wide
                        $string12_AnyplaceControl_greyware_tool_keyword = /Program\sFiles\s\(x86\)\\Anyplace\sControl/ nocase ascii wide
                        $string13_AnyplaceControl_greyware_tool_keyword = /www\.anyplace\-control\.com\/install/ nocase ascii wide

    condition:
        any of them
}