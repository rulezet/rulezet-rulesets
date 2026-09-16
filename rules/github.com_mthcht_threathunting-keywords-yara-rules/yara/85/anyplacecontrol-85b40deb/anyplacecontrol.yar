rule AnyplaceControl
{
    meta:
        description = "Detection patterns for the tool 'AnyplaceControl' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AnyplaceControl"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\/anyplace\-control\/data2\/.{0,1000}\.exe/ nocase ascii wide
                        $string2 = /\\Anyplace\sControl\s\-\sAdmin\.lnk/ nocase ascii wide
                        $string3 = /\\Anyplace\sControl\\/ nocase ascii wide
                        $string4 = /\\anyplace\-control\.ini/ nocase ascii wide
                        $string5 = /\\AppData\\Local\\Temp\\.{0,1000}\\zmstage\.exe/ nocase ascii wide
                        $string6 = /\\AppData\\Roaming\\Anyplace\sControl/ nocase ascii wide
                        $string7 = /\\Program\sFiles\s\(x86\)\\Anyplace\sControl/ nocase ascii wide
                        $string8 = /\\ProgramData\\Anyplace\sControl\s/ nocase ascii wide
                        $string9 = ">Anyplace Control Software<" nocase ascii wide
                        $string10 = "a2fa034d006bdbc3ee2a15e55eb647f8097355c288a858da1e309fe8ac1cf0a3" nocase ascii wide
                        $string11 = /AnyplaceControlInstall\.exe/ nocase ascii wide
                        $string12 = /Program\sFiles\s\(x86\)\\Anyplace\sControl/ nocase ascii wide
                        $string13 = /www\.anyplace\-control\.com\/install/ nocase ascii wide

    condition:
        any of them
}