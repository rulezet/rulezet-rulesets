rule rule_lsarelayx_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'lsarelayx' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "lsarelayx"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_lsarelayx_offensive_tool_keyword = /\/lsarelayx\.git/ nocase ascii wide
                        $string2_lsarelayx_offensive_tool_keyword = "/root/lsarelayx"
                        $string3_lsarelayx_offensive_tool_keyword = /\\\\\.\\\\pipe\\\\lsarelayx/ nocase ascii wide
                        $string4_lsarelayx_offensive_tool_keyword = /\\liblsarelay\.dll/ nocase ascii wide
                        $string5_lsarelayx_offensive_tool_keyword = /\\liblsarelayx\.dll/ nocase ascii wide
                        $string6_lsarelayx_offensive_tool_keyword = /\\lsarelayx\.cpp/ nocase ascii wide
                        $string7_lsarelayx_offensive_tool_keyword = /\\lsarelayx\.csproj/ nocase ascii wide
                        $string8_lsarelayx_offensive_tool_keyword = /\\lsarelayx\.sln/ nocase ascii wide
                        $string9_lsarelayx_offensive_tool_keyword = "CCob/lsarelayx" nocase ascii wide
                        $string10_lsarelayx_offensive_tool_keyword = "Initialised lsarelayx" nocase ascii wide
                        $string11_lsarelayx_offensive_tool_keyword = /lsarelayx\sStarting\.\.\.\./ nocase ascii wide
                        $string12_lsarelayx_offensive_tool_keyword = /lsarelayx\.exe/ nocase ascii wide
                        $string13_lsarelayx_offensive_tool_keyword = /lsarelayx_0\.1_ALPHA\.zip/ nocase ascii wide
                        $string14_lsarelayx_offensive_tool_keyword = /ntlmrelayx\.py/ nocase ascii wide
                        $string15_lsarelayx_offensive_tool_keyword = "-smb2support --no-wcf-server --no-smb-server --no-http-server" nocase ascii wide

    condition:
        any of them
}