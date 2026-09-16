rule rule_SharpExfiltrate_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SharpExfiltrate' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpExfiltrate"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_SharpExfiltrate_offensive_tool_keyword = /\.exe\sAzureStorage\s\-\-connectionstring\s.{0,1000}\s\-\-filepath\s.{0,1000}\s\-\-extensions\s/ nocase ascii wide
                        $string2_SharpExfiltrate_offensive_tool_keyword = /\.exe\sGoogleDrive\s\-\-appname\s.{0,1000}\s\-\-accesstoken\s.{0,1000}\s\-\-filepath\s.{0,1000}\s\-\-extensions\s.{0,1000}\s\-\-memoryonly/ nocase ascii wide
                        $string3_SharpExfiltrate_offensive_tool_keyword = /\.exe\sOneDrive\s\-\-username\s.{0,1000}\s\-\-password\s.{0,1000}\s\-\-filepath\s.{0,1000}\\.{0,1000}\.exe/ nocase ascii wide
                        $string4_SharpExfiltrate_offensive_tool_keyword = /\/SharpExfiltrate\.git/ nocase ascii wide
                        $string5_SharpExfiltrate_offensive_tool_keyword = "/SharpExfiltrate/" nocase ascii wide
                        $string6_SharpExfiltrate_offensive_tool_keyword = /\\SharpExfiltrate\\/ nocase ascii wide
                        $string7_SharpExfiltrate_offensive_tool_keyword = "3bb553cd-0a48-402d-9812-8daff60ac628" nocase ascii wide
                        $string8_SharpExfiltrate_offensive_tool_keyword = "Flangvik/SharpExfiltrate" nocase ascii wide
                        $string9_SharpExfiltrate_offensive_tool_keyword = /SharpExfiltrate\.csproj/ nocase ascii wide
                        $string10_SharpExfiltrate_offensive_tool_keyword = /SharpExfiltrate\.exe/ nocase ascii wide
                        $string11_SharpExfiltrate_offensive_tool_keyword = /SharpExfiltrate\.sln/ nocase ascii wide
                        $string12_SharpExfiltrate_offensive_tool_keyword = "SharpExfiltrateLootCache" nocase ascii wide
                        $string13_SharpExfiltrate_offensive_tool_keyword = "SharpExfiltrate-main" nocase ascii wide
                        $string14_SharpExfiltrate_offensive_tool_keyword = "using SharpExfiltrate" nocase ascii wide

    condition:
        any of them
}