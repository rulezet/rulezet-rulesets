rule DAMP
{
    meta:
        description = "Detection patterns for the tool 'DAMP' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DAMP"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\/DAMP\.git/ nocase ascii wide
                        $string2 = "Add-RemoteRegBackdoor" nocase ascii wide
                        $string3 = /DAMP\-master\.zip/ nocase ascii wide
                        $string4 = "Get-RemoteCachedCredential" nocase ascii wide
                        $string5 = "Get-RemoteCachedCredential" nocase ascii wide
                        $string6 = "Get-RemoteLocalAccountHash" nocase ascii wide
                        $string7 = "Get-RemoteLocalAccountHash" nocase ascii wide
                        $string8 = "Get-RemoteMachineAccountHash" nocase ascii wide
                        $string9 = "HarmJ0y/DAMP" nocase ascii wide
                        $string10 = /powerdump\.ps1/ nocase ascii wide
                        $string11 = /RemoteHashRetrieval\.ps1/ nocase ascii wide
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