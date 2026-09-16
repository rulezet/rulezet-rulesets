rule lsarelayx
{
    meta:
        description = "Detection patterns for the tool 'lsarelayx' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "lsarelayx"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/lsarelayx\.git/ nocase ascii wide
                        $string2 = "/root/lsarelayx"
                        $string3 = /\\\\\.\\\\pipe\\\\lsarelayx/ nocase ascii wide
                        $string4 = /\\liblsarelay\.dll/ nocase ascii wide
                        $string5 = /\\liblsarelayx\.dll/ nocase ascii wide
                        $string6 = /\\lsarelayx\.cpp/ nocase ascii wide
                        $string7 = /\\lsarelayx\.csproj/ nocase ascii wide
                        $string8 = /\\lsarelayx\.sln/ nocase ascii wide
                        $string9 = "CCob/lsarelayx" nocase ascii wide
                        $string10 = "Initialised lsarelayx" nocase ascii wide
                        $string11 = /lsarelayx\sStarting\.\.\.\./ nocase ascii wide
                        $string12 = /lsarelayx\.exe/ nocase ascii wide
                        $string13 = /lsarelayx_0\.1_ALPHA\.zip/ nocase ascii wide
                        $string14 = /ntlmrelayx\.py/ nocase ascii wide
                        $string15 = "-smb2support --no-wcf-server --no-smb-server --no-http-server" nocase ascii wide

    condition:
        any of them
}