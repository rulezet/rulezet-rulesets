rule PowerBreach
{
    meta:
        description = "Detection patterns for the tool 'PowerBreach' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PowerBreach"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sPowerBreach\.ps1/ nocase ascii wide
                        $string2 = "!!! THIS BACKDOOR REQUIRES FIREWALL EXCEPTION !!!" nocase ascii wide
                        $string3 = /\/PowerBreach\.ps1/ nocase ascii wide
                        $string4 = /\\PowerBreach\.ps1/ nocase ascii wide
                        $string5 = "4808ad1202bb14375f19929cb389433ffca4b27eaba4490da262a48f57b5af64" nocase ascii wide
                        $string6 = "6ce500821488255bc70acd310d8162308fd14a4fa214c79c2d9a354c705de6d7" nocase ascii wide
                        $string7 = "Add-PSFirewallRules" nocase ascii wide
                        $string8 = "Invoke-CallbackIEX" nocase ascii wide
                        $string9 = "Invoke-DeadUserBackdoor" nocase ascii wide
                        $string10 = "Invoke-EventLogBackdoor" nocase ascii wide
                        $string11 = "Invoke-LoopBackdoor" nocase ascii wide
                        $string12 = "Invoke-PortBindBackdoor" nocase ascii wide
                        $string13 = "Invoke-PortKnockBackdoor" nocase ascii wide
                        $string14 = "Invoke-ResolverBackdoor" nocase ascii wide
                        $string15 = /This\sbackdoor\srequires\sAdmin\s\:\(/ nocase ascii wide
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