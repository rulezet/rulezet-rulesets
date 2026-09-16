rule Adeleginator
{
    meta:
        description = "Detection patterns for the tool 'Adeleginator' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Adeleginator"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sADeleg\.exe/ nocase ascii wide
                        $string2 = /\$ADelegReport/ nocase ascii wide
                        $string3 = /\$InsecureResourceDelegations/ nocase ascii wide
                        $string4 = /\$InsecureTrusteeDelegations/ nocase ascii wide
                        $string5 = /\/ADeleg\.exe/ nocase ascii wide
                        $string6 = /\/ADeleginator\.git/ nocase ascii wide
                        $string7 = "/Invoke-Adeleginator" nocase ascii wide
                        $string8 = "/mtth-bfft/adeleg/releases" nocase ascii wide
                        $string9 = /\[\!\]\sInsecure\sresource\sdelegations\sfound\.\sExporting\sreport\:/ nocase ascii wide
                        $string10 = /\[\!\]\sInsecure\strustee\sdelegations\sfound\.\sExporting\sreport\:\s/ nocase ascii wide
                        $string11 = /\[\+\]\sNo\sinsecure\sresource\sdelegations\sfound\.\sEureka\!/ nocase ascii wide
                        $string12 = /\[\+\]\sNo\sinsecure\strustee\sdelegations\sfound\.\sEureka\!/ nocase ascii wide
                        $string13 = /\[i\]\sChecking\sfor\sinsecure\strustee\/resource\sdelegations/ nocase ascii wide
                        $string14 = /\[i\]\sRunning\sADeleg\sand\screating\s/ nocase ascii wide
                        $string15 = /\\ADeleg\.exe/ nocase ascii wide
                        $string16 = /\\Adeleginator\-main/ nocase ascii wide
                        $string17 = "ADeleg_InsecureResourceDelegationReport_" nocase ascii wide
                        $string18 = "ADeleg_InsecureTrusteeDelegationReport_" nocase ascii wide
                        $string19 = "Create-ADelegReport" nocase ascii wide
                        $string20 = "Find-InsecureResourceDelegations" nocase ascii wide
                        $string21 = "Go, go ADeleginator!" nocase ascii wide
                        $string22 = "Invoke-Adeleginator" nocase ascii wide
                        $string23 = "techspence/Adeleginator" nocase ascii wide
                        $string24 = /Thank\syou\sfor\susing\sADeleginator\.\sGodspeed\!\s\:O/ nocase ascii wide
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