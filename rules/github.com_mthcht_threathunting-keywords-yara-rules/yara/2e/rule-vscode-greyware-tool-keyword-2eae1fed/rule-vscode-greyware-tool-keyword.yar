rule rule_vscode_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'vscode' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "vscode"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_vscode_greyware_tool_keyword = /\.rel\.tunnels\.api\.visualstudio\.com/ nocase ascii wide
                        $string2_vscode_greyware_tool_keyword = /\\\.vscode\-cli\\code_tunnel\.json/ nocase ascii wide
                        $string3_vscode_greyware_tool_keyword = /\\download\\code\-tunnel\.exe/ nocase ascii wide
                        $string4_vscode_greyware_tool_keyword = /\\ProgramData\\.{0,1000}\\code\-tunnel\.exe/ nocase ascii wide
                        $string5_vscode_greyware_tool_keyword = /\\temp\\code\-tunnel\.exe/ nocase ascii wide
                        $string6_vscode_greyware_tool_keyword = /aue\.rel\.tunnels\.api\.visualstudio\.com/ nocase ascii wide
                        $string7_vscode_greyware_tool_keyword = /aue\-data\.rel\.tunnels\.api\.visualstudio\.com/ nocase ascii wide
                        $string8_vscode_greyware_tool_keyword = "code tunnel user login --access-token " nocase ascii wide
                        $string9_vscode_greyware_tool_keyword = /code\.exe\stunnel\s\-\-accept\-server\-license\-terms\s\-\-name\s/ nocase ascii wide
                        $string10_vscode_greyware_tool_keyword = /\-data\.rel\.tunnels\.api\.visualstudio\.com/ nocase ascii wide
                        $string11_vscode_greyware_tool_keyword = /global\.rel\.tunnels\.api\.visualstudio\.com/ nocase ascii wide
                        $string12_vscode_greyware_tool_keyword = /https\:\/\/.{0,1000}\..{0,1000}\.devtunnels\.ms/ nocase ascii wide

    condition:
        any of them
}