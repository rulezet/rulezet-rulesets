rule PAExec
{
    meta:
        description = "Detection patterns for the tool 'PAExec' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PAExec"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\s\-csrc\sC\:\\\\Windows\\\\notepad\.exe\s\-c\scmd\.exe/ nocase ascii wide
                        $string2 = " PAExec service" nocase ascii wide
                        $string3 = /\%SYSTEMROOT\%\\PAExec\-/ nocase ascii wide
                        $string4 = /\/PAExec\.cpp/ nocase ascii wide
                        $string5 = /\/paexec\.exe/ nocase ascii wide
                        $string6 = /\/PAExec\.git/ nocase ascii wide
                        $string7 = /\/paexec_eula\.txt/ nocase ascii wide
                        $string8 = /\\PAExec\.cpp/ nocase ascii wide
                        $string9 = /\\PAExec\.exe/ nocase ascii wide
                        $string10 = /\\PAEXEC\.EXE\-.{0,100}\.pf/ nocase ascii wide
                        $string11 = /\\PAExec\.log/ nocase ascii wide
                        $string12 = /\\paexec\.obj/ nocase ascii wide
                        $string13 = /\\paexec\.pdb/ nocase ascii wide
                        $string14 = /\\PAExec\.sln/ nocase ascii wide
                        $string15 = /\\PAExec\\.{0,100}\.exe/ nocase ascii wide
                        $string16 = /\\paexec_eula\.txt/ nocase ascii wide
                        $string17 = /\\PAExec_Move/ nocase ascii wide
                        $string18 = /\\pipe\\PAExecErr/ nocase ascii wide
                        $string19 = /\\pipe\\PAExecIn/ nocase ascii wide
                        $string20 = /\\pipe\\PAExecOut/ nocase ascii wide
                        $string21 = "2FEB96F5-08E6-48A3-B306-794277650A08" nocase ascii wide
                        $string22 = "2FEB96F5-08E6-48A3-B306-794277650A08" nocase ascii wide
                        $string23 = "Description'>PAExec Application" nocase ascii wide
                        $string24 = "'Details'>paexec application" nocase ascii wide
                        $string25 = "HINT: PAExec probably needs to be " nocase ascii wide
                        $string26 = /paexec\s\\\\/ nocase ascii wide
                        $string27 = "PAExec error waiting for app to exit" nocase ascii wide
                        $string28 = "PAExec service " nocase ascii wide
                        $string29 = "PAExec starting process" nocase ascii wide
                        $string30 = "PAExec timed out waiting for app to exit" nocase ascii wide
                        $string31 = /paexec\.exe\s\\\\/ nocase ascii wide
                        $string32 = /PAExec\.exe\s\-u\s/ nocase ascii wide
                        $string33 = /PAExec\-master\.zip/ nocase ascii wide
                        $string34 = /poweradmin\.com\/PAExec/ nocase ascii wide
                        $string35 = "poweradminllc/PAExec" nocase ascii wide
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