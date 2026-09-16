rule stowaway
{
    meta:
        description = "Detection patterns for the tool 'stowaway' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "stowaway"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " Author:ph4ntom" nocase ascii wide
                        $string2 = /\s\-c\s.{0,100}\s\-s\s.{0,100}\s\-\-proxy\s.{0,100}\s\-\-proxyu\s.{0,100}\s\-\-proxyp\s.{0,100}\s\-\-reconnect\s/ nocase ascii wide
                        $string3 = /\sProxyStream\s.{0,100}Stowaway/ nocase ascii wide
                        $string4 = /\/script\/reuse\.py/
                        $string5 = /\/Stowaway\.git/ nocase ascii wide
                        $string6 = "/stowaway_admin"
                        $string7 = "/stowaway_agent"
                        $string8 = /\/windows_x64_admin\.exe/ nocase ascii wide
                        $string9 = /\/windows_x64_agent\.exe/ nocase ascii wide
                        $string10 = /\/windows_x86_admin\.exe/ nocase ascii wide
                        $string11 = /\/windows_x86_agent\.exe/ nocase ascii wide
                        $string12 = /\\mipsel_agent/ nocase ascii wide
                        $string13 = /\\Stowaway\\admin\\/ nocase ascii wide
                        $string14 = /\\Stowaway\\agent\\/ nocase ascii wide
                        $string15 = /\\Stowaway\\ansicon\\/ nocase ascii wide
                        $string16 = /\\windows_x64_admin\.exe/ nocase ascii wide
                        $string17 = /\\windows_x64_agent\.exe/ nocase ascii wide
                        $string18 = /\\windows_x86_admin\.exe/ nocase ascii wide
                        $string19 = /\\windows_x86_agent\.exe/ nocase ascii wide
                        $string20 = /\]\sStarting\sagent\snode\sactively\.Connecting\sto\s.{0,100}Reconnecting\severy\s.{0,100}\sseconds/ nocase ascii wide
                        $string21 = "1df8bc4fb468ccc0fd85b553411d9b3eb7a2ba4c4a4469ae41913eef9a9e65f6" nocase ascii wide
                        $string22 = "a78d737f30e03d166d4e3e3b2dca71d54f1cbf582206dfe16a1e717ce3dc0ef7" nocase ascii wide
                        $string23 = "ac9215db682509ab2bdcba7fe924d84dafa1d8aade87172c1c6328b2cb6c9e52" nocase ascii wide
                        $string24 = /linux_x64_agent\s\-\-report\s.{0,100}\s\-l\s.{0,100}\s\-s\sph4ntom/
                        $string25 = "ph4ntonn/Stowaway" nocase ascii wide
                        $string26 = /python\sreuse\.py\s\-\-start\s\-\-rhost\s.{0,100}\s\-\-rport\s/ nocase ascii wide
                        $string27 = "release/mipsel_agent" nocase ascii wide
                        $string28 = "--socks5-proxy socks5" nocase ascii wide
                        $string29 = "--socks5-proxyp socks5" nocase ascii wide
                        $string30 = "--socks5-proxyu socks5" nocase ascii wide
                        $string31 = "'start/stop iptables port reuse'" nocase ascii wide
                        $string32 = "Stowaway/admin/process" nocase ascii wide
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
            uint16(0) == 0x5a4d or             uint16(0) == 0x457f or             uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or             uint32(0) == 0x504B0304 or             uint32(0) == 0xCAFEBABE or             uint32(0) == 0x4D534346 or             uint32(0) == 0xD0CF11E0 or             uint16(0) == 0x2321 or             uint16(0) == 0x3c3f         )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}