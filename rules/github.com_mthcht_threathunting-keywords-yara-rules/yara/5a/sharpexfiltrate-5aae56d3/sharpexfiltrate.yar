rule SharpExfiltrate
{
    meta:
        description = "Detection patterns for the tool 'SharpExfiltrate' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpExfiltrate"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\.exe\sAzureStorage\s\-\-connectionstring\s.{0,1000}\s\-\-filepath\s.{0,1000}\s\-\-extensions\s/ nocase ascii wide
                        $string2 = /\.exe\sGoogleDrive\s\-\-appname\s.{0,1000}\s\-\-accesstoken\s.{0,1000}\s\-\-filepath\s.{0,1000}\s\-\-extensions\s.{0,1000}\s\-\-memoryonly/ nocase ascii wide
                        $string3 = /\.exe\sOneDrive\s\-\-username\s.{0,1000}\s\-\-password\s.{0,1000}\s\-\-filepath\s.{0,1000}\\.{0,1000}\.exe/ nocase ascii wide
                        $string4 = /\/SharpExfiltrate\.git/ nocase ascii wide
                        $string5 = "/SharpExfiltrate/" nocase ascii wide
                        $string6 = /\\SharpExfiltrate\\/ nocase ascii wide
                        $string7 = "3bb553cd-0a48-402d-9812-8daff60ac628" nocase ascii wide
                        $string8 = "Flangvik/SharpExfiltrate" nocase ascii wide
                        $string9 = /SharpExfiltrate\.csproj/ nocase ascii wide
                        $string10 = /SharpExfiltrate\.exe/ nocase ascii wide
                        $string11 = /SharpExfiltrate\.sln/ nocase ascii wide
                        $string12 = "SharpExfiltrateLootCache" nocase ascii wide
                        $string13 = "SharpExfiltrate-main" nocase ascii wide
                        $string14 = "using SharpExfiltrate" nocase ascii wide

    condition:
        any of them
}