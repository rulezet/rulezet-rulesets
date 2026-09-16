rule rule_yakit_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'yakit' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "yakit"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_yakit_greyware_tool_keyword = /\sset\-proxy\.ps1/ nocase ascii wide
                        $string2_yakit_greyware_tool_keyword = "\"http://mitm\"" nocase ascii wide
                        $string3_yakit_greyware_tool_keyword = "/MITMPluginLogViewer" nocase ascii wide
                        $string4_yakit_greyware_tool_keyword = "/MITMServerHijacking" nocase ascii wide
                        $string5_yakit_greyware_tool_keyword = /\/set\-proxy\.ps1/ nocase ascii wide
                        $string6_yakit_greyware_tool_keyword = /\/yak_darwin_amd64\.zip/
                        $string7_yakit_greyware_tool_keyword = /\/yak_linux_amd64\.zip/
                        $string8_yakit_greyware_tool_keyword = /\/yak_windows_amd64\.zip/ nocase ascii wide
                        $string9_yakit_greyware_tool_keyword = /\?\?\sMITM\s\?\?\?\?/ nocase ascii wide
                        $string10_yakit_greyware_tool_keyword = /\\default\-yakit\.db/ nocase ascii wide
                        $string11_yakit_greyware_tool_keyword = /\\set\-proxy\.ps1/ nocase ascii wide
                        $string12_yakit_greyware_tool_keyword = /\\System32\\yak\.exe/ nocase ascii wide
                        $string13_yakit_greyware_tool_keyword = /\\yak\.exe/ nocase ascii wide
                        $string14_yakit_greyware_tool_keyword = "MITMServerHijacking/MITMPluginLocalList" nocase ascii wide
                        $string15_yakit_greyware_tool_keyword = "pwd86u1qwZ9PWevKqm1A3yAw==" nocase ascii wide
                        $string16_yakit_greyware_tool_keyword = "PwDaBjJzgufjES89Rs4Lpq63O300R/kOz30WCLo6BxxX6QVEilwSlpClnG5cZaikTA==" nocase ascii wide
                        $string17_yakit_greyware_tool_keyword = "pWDkVEtllTAK5h6cnhxNxDA==" nocase ascii wide
                        $string18_yakit_greyware_tool_keyword = /Yakit\-.{0,1000}\-windows\-amd64\.exe/ nocase ascii wide
                        $string19_yakit_greyware_tool_keyword = /Yakit\/1\.0\.0/ nocase ascii wide
                        $string20_yakit_greyware_tool_keyword = "YAKIT_MITM" nocase ascii wide
                        $string21_yakit_greyware_tool_keyword = /yakit\-remote\.json/ nocase ascii wide

    condition:
        any of them
}