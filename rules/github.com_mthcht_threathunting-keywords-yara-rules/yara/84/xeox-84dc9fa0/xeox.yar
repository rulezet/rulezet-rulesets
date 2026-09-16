rule xeox
{
    meta:
        description = "Detection patterns for the tool 'xeox' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "xeox"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\.xeox\.com/ nocase ascii wide
                        $string2 = /\\Temp\\XEOX/ nocase ascii wide
                        $string3 = /\\XEOX\\Agent\sWatchdog\son\sBoot/ nocase ascii wide
                        $string4 = /\\XEOX\\Agent\sWatchdog\son\sWakeup/ nocase ascii wide
                        $string5 = /\\XEOX\\Agent\sWatchdog/ nocase ascii wide
                        $string6 = /\\XEOX_cloud_agent_install\.bat/ nocase ascii wide
                        $string7 = /\\XEOXAgent\.exe/ nocase ascii wide
                        $string8 = /\\xeox\-agent_x64\\/ nocase ascii wide
                        $string9 = /agent01\.xeox\.com/ nocase ascii wide
                        $string10 = "echo Installing XEOX Agent" nocase ascii wide
                        $string11 = /https\:\/\/portal\.xeox\.com\// nocase ascii wide
                        $string12 = /ProgramFiles\(x86\)\\xeox\\/ nocase ascii wide
                        $string13 = /ProgramFiles\\xeox\\/ nocase ascii wide
                        $string14 = "ui/rest/download/xeoxagentgeneric/" nocase ascii wide
                        $string15 = "XEOX Agent for Windows" nocase ascii wide
                        $string16 = "XEOX Agent Service" nocase ascii wide
                        $string17 = /xeox\.com\/ui\/download\// nocase ascii wide
                        $string18 = /xeox_service_windows\.exe/ nocase ascii wide
                        $string19 = /xeox\-agent_.{0,100}\.exe/ nocase ascii wide
                        $string20 = /xeox\-agent_x64\.exe/ nocase ascii wide
                        $string21 = /xeox\-agent_x86\.exe/ nocase ascii wide
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