rule Invoke_ADEnum
{
    meta:
        description = "Detection patterns for the tool 'Invoke-ADEnum' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-ADEnum"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " -Recommended -SprayEmptyPasswords" nocase ascii wide
                        $string2 = /\$EmptyPasswordUsers/ nocase ascii wide
                        $string3 = /\$PotentialComputersWithEmptyPassword/ nocase ascii wide
                        $string4 = /\$PotentialUsersWithEmptyPassword/ nocase ascii wide
                        $string5 = /\$SprayEmptyPasswords/ nocase ascii wide
                        $string6 = /\/Invoke\-ADEnum\.git/ nocase ascii wide
                        $string7 = /\\.{0,100}_AD\-Audit_.{0,100}\.txt/ nocase ascii wide
                        $string8 = /\\Invoke\-ADEnum\\/ nocase ascii wide
                        $string9 = /\\Invoke\-ADEnum\-main/ nocase ascii wide
                        $string10 = /\\krbtgtAccounts\.json/ nocase ascii wide
                        $string11 = /\]\sCollecting\sKrbtgt/ nocase ascii wide
                        $string12 = "27049d9f4a7125e9be92e84edcad5dc118bc8503920fb3250b3e2f7577370b49" nocase ascii wide
                        $string13 = "Find-LocalAdminAccess " nocase ascii wide
                        $string14 = "Invoke-ADEnum -" nocase ascii wide
                        $string15 = /Invoke\-ADEnum\.ps1/ nocase ascii wide
                        $string16 = "Invoke-ShareHunter " nocase ascii wide
                        $string17 = "Leo4j/Invoke-ADEnum" nocase ascii wide
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