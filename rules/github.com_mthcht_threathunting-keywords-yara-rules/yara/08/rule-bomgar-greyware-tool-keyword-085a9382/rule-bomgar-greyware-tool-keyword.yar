rule rule_Bomgar_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Bomgar' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Bomgar"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_Bomgar_greyware_tool_keyword = /\.beyondtrustcloud\.com\/session_complete/ nocase ascii wide
                        $string2_Bomgar_greyware_tool_keyword = /\/bomgar\-rep\.exe/ nocase ascii wide
                        $string3_Bomgar_greyware_tool_keyword = /\/bomgar\-rep\-installer\.exe/ nocase ascii wide
                        $string4_Bomgar_greyware_tool_keyword = /\/bomgar\-scc\-.{0,1000}\.exe/ nocase ascii wide
                        $string5_Bomgar_greyware_tool_keyword = /\/bomgar\-scc\.exe/ nocase ascii wide
                        $string6_Bomgar_greyware_tool_keyword = /\\appdata\\local\\bomgar\\bomgar\-rep\\/ nocase ascii wide
                        $string7_Bomgar_greyware_tool_keyword = /\\Bomgar\-enum_cp\-/ nocase ascii wide
                        $string8_Bomgar_greyware_tool_keyword = /\\bomgar\-rep\.cache\\/ nocase ascii wide
                        $string9_Bomgar_greyware_tool_keyword = /\\bomgar\-rep\.exe/ nocase ascii wide
                        $string10_Bomgar_greyware_tool_keyword = /\\bomgar\-rep\-installer\.exe/ nocase ascii wide
                        $string11_Bomgar_greyware_tool_keyword = /\\bomgar\-scc\-.{0,1000}\.exe/ nocase ascii wide
                        $string12_Bomgar_greyware_tool_keyword = /\\bomgar\-scc\.exe/ nocase ascii wide
                        $string13_Bomgar_greyware_tool_keyword = /\\BOMGAR\-SCC\.EXE\-/ nocase ascii wide
                        $string14_Bomgar_greyware_tool_keyword = /\\cbhook\-x86\.dll/ nocase ascii wide
                        $string15_Bomgar_greyware_tool_keyword = /\\CurrentVersion\\Run\\Bomgar\sSupport\sReconnect/ nocase ascii wide
                        $string16_Bomgar_greyware_tool_keyword = /\\CurrentVersion\\Uninstall\\Representative\sConsole\s\[eval\-/ nocase ascii wide
                        $string17_Bomgar_greyware_tool_keyword = /\\embedhook\-x64\.exe/ nocase ascii wide
                        $string18_Bomgar_greyware_tool_keyword = /\\embedhook\-x86\.exe/ nocase ascii wide
                        $string19_Bomgar_greyware_tool_keyword = /\\programdata\\bomgar\-scc\-/ nocase ascii wide
                        $string20_Bomgar_greyware_tool_keyword = ">Bomgar Corporation</Data>" nocase ascii wide
                        $string21_Bomgar_greyware_tool_keyword = ">Remote Support Customer Client</Data>" nocase ascii wide
                        $string22_Bomgar_greyware_tool_keyword = ">Representative Console</Data>" nocase ascii wide
                        $string23_Bomgar_greyware_tool_keyword = /beyondtrustcloud\.com\\Software\\Qt6/ nocase ascii wide
                        $string24_Bomgar_greyware_tool_keyword = /bomgar\-rdp\.exe/ nocase ascii wide
                        $string25_Bomgar_greyware_tool_keyword = "'Company'>BeyondTrust</Data>" nocase ascii wide
                        $string26_Bomgar_greyware_tool_keyword = "'Company'>bomgar</Data>" nocase ascii wide
                        $string27_Bomgar_greyware_tool_keyword = /eval\-.{0,1000}\.beyondtrustcloud\.com/ nocase ascii wide
                        $string28_Bomgar_greyware_tool_keyword = /license\.bomgar\.com/ nocase ascii wide
                        $string29_Bomgar_greyware_tool_keyword = /\'TaskName\'\>\\Bomgar\sTask\s/ nocase ascii wide
                        $string30_Bomgar_greyware_tool_keyword = /To\:\sAll\sRepresentatives\s\sFrom\:\sRemote\sSupport\s.{0,1000}\shas\sadded\sa\snote\sto\sthis\ssession\./ nocase ascii wide

    condition:
        any of them
}