rule rule_DumpAADSyncCreds_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'DumpAADSyncCreds' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DumpAADSyncCreds"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_DumpAADSyncCreds_offensive_tool_keyword = /\/DumpAADSyncCreds\.git/ nocase ascii wide
                        $string2_DumpAADSyncCreds_offensive_tool_keyword = /\[\+\]\sObtained\sADSync\sservice\saccount\stoken\sfrom\smiiserver\sprocess/ nocase ascii wide
                        $string3_DumpAADSyncCreds_offensive_tool_keyword = "95A40D7C-F3F7-4C45-8C5A-D384DE50B6C9" nocase ascii wide
                        $string4_DumpAADSyncCreds_offensive_tool_keyword = "ADSync passwords can be read or modified as local administrator only for ADSync version " nocase ascii wide
                        $string5_DumpAADSyncCreds_offensive_tool_keyword = "Dump AAD connect account credential in current context" nocase ascii wide
                        $string6_DumpAADSyncCreds_offensive_tool_keyword = /DumpAADSyncCreds\.csproj/ nocase ascii wide
                        $string7_DumpAADSyncCreds_offensive_tool_keyword = /DumpAADSyncCreds\.exe/ nocase ascii wide
                        $string8_DumpAADSyncCreds_offensive_tool_keyword = /DumpAADSyncCreds\.sln/ nocase ascii wide
                        $string9_DumpAADSyncCreds_offensive_tool_keyword = "e6e05a88178633c271919ae5ea4c9633991774e2fd345ffe3052c209e2ef31d5" nocase ascii wide
                        $string10_DumpAADSyncCreds_offensive_tool_keyword = "Hagrid29/DumpAADSyncCreds" nocase ascii wide
                        $string11_DumpAADSyncCreds_offensive_tool_keyword = "P@ss4Hagrid29" nocase ascii wide

    condition:
        any of them
}