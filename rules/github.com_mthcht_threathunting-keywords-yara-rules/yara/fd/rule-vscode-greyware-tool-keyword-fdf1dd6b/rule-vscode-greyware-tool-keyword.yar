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
                        $string4_vscode_greyware_tool_keyword = /\\ProgramData\\.{0,100}\\code\-tunnel\.exe/ nocase ascii wide
                        $string5_vscode_greyware_tool_keyword = /\\temp\\code\-tunnel\.exe/ nocase ascii wide
                        $string6_vscode_greyware_tool_keyword = /aue\.rel\.tunnels\.api\.visualstudio\.com/ nocase ascii wide
                        $string7_vscode_greyware_tool_keyword = /aue\-data\.rel\.tunnels\.api\.visualstudio\.com/ nocase ascii wide
                        $string8_vscode_greyware_tool_keyword = "code tunnel user login --access-token " nocase ascii wide
                        $string9_vscode_greyware_tool_keyword = /code\.exe\stunnel\s\-\-accept\-server\-license\-terms\s\-\-name\s/ nocase ascii wide
                        $string10_vscode_greyware_tool_keyword = /\-data\.rel\.tunnels\.api\.visualstudio\.com/ nocase ascii wide
                        $string11_vscode_greyware_tool_keyword = /global\.rel\.tunnels\.api\.visualstudio\.com/ nocase ascii wide
                        $string12_vscode_greyware_tool_keyword = /https\:\/\/.{0,100}\..{0,100}\.devtunnels\.ms/ nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or             uint16(0) == 0x457f or             uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or             uint32(0) == 0x504B0304 or             uint32(0) == 0xCAFEBABE or             uint32(0) == 0x4D534346 or             uint32(0) == 0xD0CF11E0 or             uint16(0) == 0x2321 or             uint16(0) == 0x3c3f         )) and any of ($string*)) or
        (filesize < 2MB and
        (
            any of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}