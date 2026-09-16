rule rule_localtunnels_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'localtunnels' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "localtunnels"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_localtunnels_greyware_tool_keyword = " install localtunnel" nocase ascii wide
                        $string2_localtunnels_greyware_tool_keyword = " localtunnel-server" nocase ascii wide
                        $string3_localtunnels_greyware_tool_keyword = /\/localtunnel\.git/ nocase ascii wide
                        $string4_localtunnels_greyware_tool_keyword = /\/localtunnel\-server\.git/ nocase ascii wide
                        $string5_localtunnels_greyware_tool_keyword = "37e85dd1f3987fcc566c1b29bda5b94e4b2fd129a39cc7eeba3af7a69a0cdb09" nocase ascii wide
                        $string6_localtunnels_greyware_tool_keyword = "6f44dd5e572279979a9a59b0186a9fb2805be4c6decbcc438cf2b9d2c17f3a42" nocase ascii wide
                        $string7_localtunnels_greyware_tool_keyword = "aba729428bafe6508191a79e06c7399a19cf80bf0c382eecca951655aab6e00a" nocase ascii wide
                        $string8_localtunnels_greyware_tool_keyword = "bin/lt --host https://" nocase ascii wide
                        $string9_localtunnels_greyware_tool_keyword = /https\:\/\/.{0,100}\.localtunnel\.me/ nocase ascii wide
                        $string10_localtunnels_greyware_tool_keyword = /https\:\/\/localtunnel\.me/ nocase ascii wide
                        $string11_localtunnels_greyware_tool_keyword = /localtunnel\.github\.io\/www\// nocase ascii wide
                        $string12_localtunnels_greyware_tool_keyword = "localtunnel/localtunnel" nocase ascii wide
                        $string13_localtunnels_greyware_tool_keyword = "localtunnel/nginx" nocase ascii wide
                        $string14_localtunnels_greyware_tool_keyword = "localtunnel/server" nocase ascii wide
                        $string15_localtunnels_greyware_tool_keyword = "npm install -g localtunnel" nocase ascii wide
                        $string16_localtunnels_greyware_tool_keyword = "npm install -g localtunnel" nocase ascii wide
                        $string17_localtunnels_greyware_tool_keyword = "npx localtunnel --port " nocase ascii wide
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