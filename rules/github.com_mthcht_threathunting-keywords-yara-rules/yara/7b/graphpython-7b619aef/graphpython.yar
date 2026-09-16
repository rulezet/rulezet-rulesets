rule Graphpython
{
    meta:
        description = "Detection patterns for the tool 'Graphpython' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Graphpython"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sbackdoored\-script\.ps1/ nocase ascii wide
                        $string2 = /\sGraphpython\.py/ nocase ascii wide
                        $string3 = /\sKillchain\.ps1/ nocase ascii wide
                        $string4 = /\/backdoored\-script\.ps1/ nocase ascii wide
                        $string5 = /\/Graphpython\.git/ nocase ascii wide
                        $string6 = /\/Graphpython\.py/ nocase ascii wide
                        $string7 = /\/Killchain\.ps1/ nocase ascii wide
                        $string8 = /\\backdoored\-script\.ps1/ nocase ascii wide
                        $string9 = /\\Graphpython\.py/ nocase ascii wide
                        $string10 = /\\Killchain\.ps1/ nocase ascii wide
                        $string11 = "38707a769a7eb4bd3e4165eaa94d727b33e7a83d974464c5f6a4fb9d6ef7d43f" nocase ascii wide
                        $string12 = "6f3c6aacdcbeacc32a31e6ad49ac47e3f9d315ef277fe75125f7e596b592310e" nocase ascii wide
                        $string13 = "9dab89ef77aae50a68e256bf169057ea3083869c80a3caddccbddecc5b4f61f7" nocase ascii wide
                        $string14 = "--command assign-privilegedrole --token " nocase ascii wide
                        $string15 = "--command backdoor-script --id " nocase ascii wide
                        $string16 = "--command deploy-maliciousscript --script " nocase ascii wide
                        $string17 = "--command invoke-reconasoutsider --domain " nocase ascii wide
                        $string18 = "--command invoke-userenumerationasoutsider --username " nocase ascii wide
                        $string19 = "--command spoof-owaemailmessage " nocase ascii wide
                        $string20 = /dump_owamailbox\(/ nocase ascii wide
                        $string21 = /Graphpython\.__main__/ nocase ascii wide
                        $string22 = /Graphpython\.utils\.helpers/ nocase ascii wide
                        $string23 = "Invoke-AADIntReconAsGuest" nocase ascii wide
                        $string24 = "Invoke-AADIntUserEnumerationAsGuest" nocase ascii wide
                        $string25 = "Invoke-ESTSCookieToAccessToken" nocase ascii wide
                        $string26 = "Invoke-MFASweep" nocase ascii wide
                        $string27 = "Invoke-UserEnumerationAsOutsider" nocase ascii wide
                        $string28 = "mlcsec/Graphpython" nocase ascii wide
                        $string29 = /mlcsec\@proton\.me/ nocase ascii wide
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