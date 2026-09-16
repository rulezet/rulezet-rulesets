rule Bomgar
{
    meta:
        description = "Detection patterns for the tool 'Bomgar' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Bomgar"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\.beyondtrustcloud\.com\/session_complete/ nocase ascii wide
                        $string2 = /\/bomgar\-rep\.exe/ nocase ascii wide
                        $string3 = /\/bomgar\-rep\-installer\.exe/ nocase ascii wide
                        $string4 = /\/bomgar\-scc\-.{0,1000}\.exe/ nocase ascii wide
                        $string5 = /\/bomgar\-scc\.exe/ nocase ascii wide
                        $string6 = /\\appdata\\local\\bomgar\\bomgar\-rep\\/ nocase ascii wide
                        $string7 = /\\Bomgar\-enum_cp\-/ nocase ascii wide
                        $string8 = /\\bomgar\-rep\.cache\\/ nocase ascii wide
                        $string9 = /\\bomgar\-rep\.exe/ nocase ascii wide
                        $string10 = /\\bomgar\-rep\-installer\.exe/ nocase ascii wide
                        $string11 = /\\bomgar\-scc\-.{0,1000}\.exe/ nocase ascii wide
                        $string12 = /\\bomgar\-scc\.exe/ nocase ascii wide
                        $string13 = /\\BOMGAR\-SCC\.EXE\-/ nocase ascii wide
                        $string14 = /\\cbhook\-x86\.dll/ nocase ascii wide
                        $string15 = /\\CurrentVersion\\Run\\Bomgar\sSupport\sReconnect/ nocase ascii wide
                        $string16 = /\\CurrentVersion\\Uninstall\\Representative\sConsole\s\[eval\-/ nocase ascii wide
                        $string17 = /\\embedhook\-x64\.exe/ nocase ascii wide
                        $string18 = /\\embedhook\-x86\.exe/ nocase ascii wide
                        $string19 = /\\programdata\\bomgar\-scc\-/ nocase ascii wide
                        $string20 = ">Bomgar Corporation</Data>" nocase ascii wide
                        $string21 = ">Remote Support Customer Client</Data>" nocase ascii wide
                        $string22 = ">Representative Console</Data>" nocase ascii wide
                        $string23 = /beyondtrustcloud\.com\\Software\\Qt6/ nocase ascii wide
                        $string24 = /bomgar\-rdp\.exe/ nocase ascii wide
                        $string25 = "'Company'>BeyondTrust</Data>" nocase ascii wide
                        $string26 = "'Company'>bomgar</Data>" nocase ascii wide
                        $string27 = /eval\-.{0,1000}\.beyondtrustcloud\.com/ nocase ascii wide
                        $string28 = /license\.bomgar\.com/ nocase ascii wide
                        $string29 = /\'TaskName\'\>\\Bomgar\sTask\s/ nocase ascii wide
                        $string30 = /To\:\sAll\sRepresentatives\s\sFrom\:\sRemote\sSupport\s.{0,1000}\shas\sadded\sa\snote\sto\sthis\ssession\./ nocase ascii wide

    condition:
        any of them
}