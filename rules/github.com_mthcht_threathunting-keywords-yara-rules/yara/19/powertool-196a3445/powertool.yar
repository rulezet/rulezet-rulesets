rule Powertool
{
    meta:
        description = "Detection patterns for the tool 'Powertool' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Powertool"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\[PowerTool\]\sname\=\%s\,\ssize\=\%d\,\s\%d/ nocase ascii wide
                        $string2 = /\\PowerTool\.exe/ nocase ascii wide
                        $string3 = /\\PowerTool\.pdb/ nocase ascii wide
                        $string4 = /\\PowerTool32\.exe/ nocase ascii wide
                        $string5 = /\\PowerTool64\.exe/ nocase ascii wide
                        $string6 = "094d1476331d6f693f1d546b53f1c1a42863e6cde014e2ed655f3cbe63e5ecde" nocase ascii wide
                        $string7 = "611db45c564ffb1b67a85b2249f30e5a95f2b7ab2ceec403cb22555a708c61d9" nocase ascii wide
                        $string8 = "Chage language nedd to restart PowerTool" nocase ascii wide
                        $string9 = "Chage language nedd to restart PowerTool" nocase ascii wide
                        $string10 = "d321ce59062c8d96dacdfe13e84d1543a296c432291dd4488d79f6b94a565923" nocase ascii wide
                        $string11 = "Detection may be stuck, First confirm whether the device hijack in " nocase ascii wide
                        $string12 = /d\-h\.st\/users\/powertool/ nocase ascii wide
                        $string13 = /whether\sto\sdownload\sthe\s64bit\sversion\sof\sPowerTool\?/ nocase ascii wide
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