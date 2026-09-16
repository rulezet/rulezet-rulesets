rule pspy
{
    meta:
        description = "Detection patterns for the tool 'pspy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pspy"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "/bin/pspsy"
                        $string2 = /\/download\/v1\.1\.0\/pspy32/
                        $string3 = /\/download\/v1\.1\.0\/pspy64/
                        $string4 = /\/download\/v1\.2\.0\/pspy32/
                        $string5 = /\/download\/v1\.2\.1\/pspy32/
                        $string6 = /\/download\/v1\.2\.1\/pspy64/
                        $string7 = "/pspy -"
                        $string8 = /\/pspy\.git/
                        $string9 = /\/pspy\.git/
                        $string10 = /\/pspy\.go/
                        $string11 = "/pspy/cmd"
                        $string12 = "/pspy/cmd/"
                        $string13 = /\/pspy\/pspy\.go/
                        $string14 = "/pspy32"
                        $string15 = "/pspy64"
                        $string16 = /\/psscanner\.go/
                        $string17 = /\/psscanner\/psscanner\.go/
                        $string18 = /\[\+\]\sDropping\sinto\sshell/
                        $string19 = /\[\+\]\sStarting\spspy\snow/
                        $string20 = /\\pspy\\pspy\.go/
                        $string21 = /\\psscanner\\psscanner\.go/
                        $string22 = "3d770299898ab069e0a7f139ed0659991feeb17f73e55b398bf982932c200ef9"
                        $string23 = /Complete\slog\sof\spspy\s\(may\scontain\scommands\srun\sin\sthis\stest\)\:/
                        $string24 = "docker run -it --rm local/pspy"
                        $string25 = "DominicBreuker/pspy"
                        $string26 = "DominicBreuker/pspy"
                        $string27 = "pspy - version: "
                        $string28 = /pspy.{0,100}psscanner/
                        $string29 = "pspy32 -"
                        $string30 = "pspy64 -"
                        $string31 = "pspy64 -p"
                        $string32 = "pspy64 -r "
                        $string33 = "pspy-build:latest"
                        $string34 = "pspy-development:latest"
                        $string35 = "pspy-example:latest"
                        $string36 = "pspy-master"
                        $string37 = "pspy-testing:latest"
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