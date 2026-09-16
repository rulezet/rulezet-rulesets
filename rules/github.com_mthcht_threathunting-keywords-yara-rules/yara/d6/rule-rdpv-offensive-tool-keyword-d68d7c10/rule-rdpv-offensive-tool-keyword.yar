rule rule_rdpv_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'rdpv' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "rdpv"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_rdpv_offensive_tool_keyword = /\srdpv\.exe/ nocase ascii wide
                        $string2_rdpv_offensive_tool_keyword = /\/rdpv\.exe/ nocase ascii wide
                        $string3_rdpv_offensive_tool_keyword = /\/toolsdownload\/rdpv\.zip/ nocase ascii wide
                        $string4_rdpv_offensive_tool_keyword = /\\rdpv\.exe/ nocase ascii wide
                        $string5_rdpv_offensive_tool_keyword = ">Password Recovery for Remote Desktop<" nocase ascii wide
                        $string6_rdpv_offensive_tool_keyword = ">Remote Desktop PassView<" nocase ascii wide
                        $string7_rdpv_offensive_tool_keyword = "205818e10c13d2e51b4c0196ca30111276ca1107fc8e25a0992fe67879eab964" nocase ascii wide
                        $string8_rdpv_offensive_tool_keyword = "528de69797c36423a1e6b64fa8b1825f354e6707f2ca3760d81a9f58d69d58bb" nocase ascii wide
                        $string9_rdpv_offensive_tool_keyword = /RemoteDesktopPassView\.zip/ nocase ascii wide

    condition:
        any of them
}