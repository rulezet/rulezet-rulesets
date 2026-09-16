rule vscode
{
    meta:
        description = "Detection patterns for the tool 'vscode' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "vscode"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\.rel\.tunnels\.api\.visualstudio\.com/ nocase ascii wide
                        $string2 = /\\\.vscode\-cli\\code_tunnel\.json/ nocase ascii wide
                        $string3 = /\\download\\code\-tunnel\.exe/ nocase ascii wide
                        $string4 = /\\ProgramData\\.{0,1000}\\code\-tunnel\.exe/ nocase ascii wide
                        $string5 = /\\temp\\code\-tunnel\.exe/ nocase ascii wide
                        $string6 = /aue\.rel\.tunnels\.api\.visualstudio\.com/ nocase ascii wide
                        $string7 = /aue\-data\.rel\.tunnels\.api\.visualstudio\.com/ nocase ascii wide
                        $string8 = "code tunnel user login --access-token " nocase ascii wide
                        $string9 = /code\.exe\stunnel\s\-\-accept\-server\-license\-terms\s\-\-name\s/ nocase ascii wide
                        $string10 = /\-data\.rel\.tunnels\.api\.visualstudio\.com/ nocase ascii wide
                        $string11 = /global\.rel\.tunnels\.api\.visualstudio\.com/ nocase ascii wide
                        $string12 = /https\:\/\/.{0,1000}\..{0,1000}\.devtunnels\.ms/ nocase ascii wide

    condition:
        any of them
}