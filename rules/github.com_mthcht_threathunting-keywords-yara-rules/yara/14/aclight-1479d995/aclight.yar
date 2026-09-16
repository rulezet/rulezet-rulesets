rule ACLight
{
    meta:
        description = "Detection patterns for the tool 'ACLight' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ACLight"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\s\-\sSensitive\sAccounts\.csv/ nocase ascii wide
                        $string2 = /\/ACLight\.git/ nocase ascii wide
                        $string3 = "/ACLight/" nocase ascii wide
                        $string4 = /\\scanACLsResults\.csv/ nocase ascii wide
                        $string5 = /Accounts\swith\sextra\spermissions\.txt/ nocase ascii wide
                        $string6 = /ACLight\.ps1/ nocase ascii wide
                        $string7 = /ACLight\.psd1/ nocase ascii wide
                        $string8 = /ACLight\.psm1/ nocase ascii wide
                        $string9 = /ACLight2\.ps1/ nocase ascii wide
                        $string10 = /ACLight2\.psd1/ nocase ascii wide
                        $string11 = /ACLight2\.psm1/ nocase ascii wide
                        $string12 = "ACLight-master" nocase ascii wide
                        $string13 = "cyberark/ACLight" nocase ascii wide
                        $string14 = /Execute\-ACLight\.bat/ nocase ascii wide
                        $string15 = /Execute\-ACLight2\.bat/ nocase ascii wide
                        $string16 = "Invoke-ACLcsvFileAnalysis" nocase ascii wide
                        $string17 = /Invoke\-ACLScanner\s.{0,100}\s\-Filter\s/ nocase ascii wide
                        $string18 = /Invoke\-ACLScanner\s.{0,100}\s\-Name\s/ nocase ascii wide
                        $string19 = /Privileged\sAccounts\s\-\sLayers\sAnalysis\.txt/ nocase ascii wide
                        $string20 = /Privileged\sAccounts\sPermissions\s\-\sFinal\sReport\.csv/ nocase ascii wide
                        $string21 = /Privileged\sAccounts\sPermissions\s\-\sIrregular\sAccounts\.csv/ nocase ascii wide
                        $string22 = "Start-ACLsAnalysis -Domain" nocase ascii wide
                        $string23 = "Start-domainACLsAnalysis" nocase ascii wide
                        $string24 = "starting Multi-Layered ACLight scan" nocase ascii wide
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