rule localtunnel
{
    meta:
        description = "Detection patterns for the tool 'localtunnel' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "localtunnel"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = " --name localtunnel " nocase ascii wide
                        $string2 = /\.localltunnel\.me/ nocase ascii wide
                        $string3 = /\/go\-localtunnel\.git/ nocase ascii wide
                        $string4 = /\/gotunnelme\.git/ nocase ascii wide
                        $string5 = /\/localtunnel\.git/ nocase ascii wide
                        $string6 = /\/localtunnel\.js/ nocase ascii wide
                        $string7 = "d0274f036468ef236d3a526bb6235289bdbe4c8828ee7feee1829a026f5f3bec" nocase ascii wide
                        $string8 = "e367bbc84b75901ae680472b7b848ee4f10fbc356e7dd8de5c2c46000cf78818" nocase ascii wide
                        $string9 = "gotunnelme " nocase ascii wide
                        $string10 = /https\:\/\/localtunnel\.me/ nocase ascii wide
                        $string11 = "install -g localtunnel" nocase ascii wide
                        $string12 = "localtunnel/go-localtunnel" nocase ascii wide
                        $string13 = /localtunnel\/server\.git/ nocase ascii wide
                        $string14 = "localtunnel-server:latest" nocase ascii wide
                        $string15 = "NoahShen/gotunnelme" nocase ascii wide
                        $string16 = "npx localtunnel " nocase ascii wide
                        $string17 = "src/gotunnelme/" nocase ascii wide
                        $string18 = "yarn add localtunnel" nocase ascii wide
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