rule rule_Invoke_ADEnum_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Invoke-ADEnum' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-ADEnum"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Invoke_ADEnum_offensive_tool_keyword = " -Recommended -SprayEmptyPasswords" nocase ascii wide
                        $string2_Invoke_ADEnum_offensive_tool_keyword = /\$EmptyPasswordUsers/ nocase ascii wide
                        $string3_Invoke_ADEnum_offensive_tool_keyword = /\$PotentialComputersWithEmptyPassword/ nocase ascii wide
                        $string4_Invoke_ADEnum_offensive_tool_keyword = /\$PotentialUsersWithEmptyPassword/ nocase ascii wide
                        $string5_Invoke_ADEnum_offensive_tool_keyword = /\$SprayEmptyPasswords/ nocase ascii wide
                        $string6_Invoke_ADEnum_offensive_tool_keyword = /\/Invoke\-ADEnum\.git/ nocase ascii wide
                        $string7_Invoke_ADEnum_offensive_tool_keyword = /\\.{0,100}_AD\-Audit_.{0,100}\.txt/ nocase ascii wide
                        $string8_Invoke_ADEnum_offensive_tool_keyword = /\\Invoke\-ADEnum\\/ nocase ascii wide
                        $string9_Invoke_ADEnum_offensive_tool_keyword = /\\Invoke\-ADEnum\-main/ nocase ascii wide
                        $string10_Invoke_ADEnum_offensive_tool_keyword = /\\krbtgtAccounts\.json/ nocase ascii wide
                        $string11_Invoke_ADEnum_offensive_tool_keyword = /\]\sCollecting\sKrbtgt/ nocase ascii wide
                        $string12_Invoke_ADEnum_offensive_tool_keyword = "27049d9f4a7125e9be92e84edcad5dc118bc8503920fb3250b3e2f7577370b49" nocase ascii wide
                        $string13_Invoke_ADEnum_offensive_tool_keyword = "Find-LocalAdminAccess " nocase ascii wide
                        $string14_Invoke_ADEnum_offensive_tool_keyword = "Invoke-ADEnum -" nocase ascii wide
                        $string15_Invoke_ADEnum_offensive_tool_keyword = /Invoke\-ADEnum\.ps1/ nocase ascii wide
                        $string16_Invoke_ADEnum_offensive_tool_keyword = "Invoke-ShareHunter " nocase ascii wide
                        $string17_Invoke_ADEnum_offensive_tool_keyword = "Leo4j/Invoke-ADEnum" nocase ascii wide
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