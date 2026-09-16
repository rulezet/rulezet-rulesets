rule adaudit
{
    meta:
        description = "Detection patterns for the tool 'adaudit' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "adaudit"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\sadaudit\.ps1/ nocase ascii wide
                        $string2 = /\/adaudit\.git/ nocase ascii wide
                        $string3 = /\/adaudit\.ps1/ nocase ascii wide
                        $string4 = /\[\!\]\sAS\-REP\sRoastable\suser\:/ nocase ascii wide
                        $string5 = /\[\+\]\sNTDS\.dit\,\sSYSTEM\s\&\sSAM\ssaved\sto\soutput\sfolder/ nocase ascii wide
                        $string6 = /\[\+\]\sUse\ssecretsdump\.py/ nocase ascii wide
                        $string7 = /\\adaudit\.ps1/ nocase ascii wide
                        $string8 = "54709655b001aa4d02b8040574970decd2e185a1ca4effbf87eb94574b9c87a0" nocase ascii wide
                        $string9 = "Find-DangerousACLPermissions" nocase ascii wide
                        $string10 = "Get-ADUsersWithoutPreAuth" nocase ascii wide
                        $string11 = "phillips321/adaudit" nocase ascii wide
                        $string12 = "Search-ADAccount -PasswordNeverExpires -UsersOnly" nocase ascii wide
                        $string13 = /Write\-Nessus\-Finding\(/ nocase ascii wide
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