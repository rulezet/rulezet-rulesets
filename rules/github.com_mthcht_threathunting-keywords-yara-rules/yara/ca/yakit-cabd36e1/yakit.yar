rule yakit
{
    meta:
        description = "Detection patterns for the tool 'yakit' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "yakit"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\sset\-proxy\.ps1/ nocase ascii wide
                        $string2 = "\"http://mitm\"" nocase ascii wide
                        $string3 = "/MITMPluginLogViewer" nocase ascii wide
                        $string4 = "/MITMServerHijacking" nocase ascii wide
                        $string5 = /\/set\-proxy\.ps1/ nocase ascii wide
                        $string6 = /\/yak_darwin_amd64\.zip/
                        $string7 = /\/yak_linux_amd64\.zip/
                        $string8 = /\/yak_windows_amd64\.zip/ nocase ascii wide
                        $string9 = /\?\?\sMITM\s\?\?\?\?/ nocase ascii wide
                        $string10 = /\\default\-yakit\.db/ nocase ascii wide
                        $string11 = /\\set\-proxy\.ps1/ nocase ascii wide
                        $string12 = /\\System32\\yak\.exe/ nocase ascii wide
                        $string13 = /\\yak\.exe/ nocase ascii wide
                        $string14 = "MITMServerHijacking/MITMPluginLocalList" nocase ascii wide
                        $string15 = "pwd86u1qwZ9PWevKqm1A3yAw==" nocase ascii wide
                        $string16 = "PwDaBjJzgufjES89Rs4Lpq63O300R/kOz30WCLo6BxxX6QVEilwSlpClnG5cZaikTA==" nocase ascii wide
                        $string17 = "pWDkVEtllTAK5h6cnhxNxDA==" nocase ascii wide
                        $string18 = /Yakit\-.{0,1000}\-windows\-amd64\.exe/ nocase ascii wide
                        $string19 = /Yakit\/1\.0\.0/ nocase ascii wide
                        $string20 = "YAKIT_MITM" nocase ascii wide
                        $string21 = /yakit\-remote\.json/ nocase ascii wide

    condition:
        any of them
}