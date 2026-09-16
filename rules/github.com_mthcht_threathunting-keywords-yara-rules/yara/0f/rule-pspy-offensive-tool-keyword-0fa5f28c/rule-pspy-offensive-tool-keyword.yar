rule rule_pspy_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'pspy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pspy"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_pspy_offensive_tool_keyword = "/bin/pspsy"
                        $string2_pspy_offensive_tool_keyword = /\/download\/v1\.1\.0\/pspy32/
                        $string3_pspy_offensive_tool_keyword = /\/download\/v1\.1\.0\/pspy64/
                        $string4_pspy_offensive_tool_keyword = /\/download\/v1\.2\.0\/pspy32/
                        $string5_pspy_offensive_tool_keyword = /\/download\/v1\.2\.1\/pspy32/
                        $string6_pspy_offensive_tool_keyword = /\/download\/v1\.2\.1\/pspy64/
                        $string7_pspy_offensive_tool_keyword = "/pspy -"
                        $string8_pspy_offensive_tool_keyword = /\/pspy\.git/
                        $string9_pspy_offensive_tool_keyword = /\/pspy\.git/
                        $string10_pspy_offensive_tool_keyword = /\/pspy\.go/
                        $string11_pspy_offensive_tool_keyword = "/pspy/cmd"
                        $string12_pspy_offensive_tool_keyword = "/pspy/cmd/"
                        $string13_pspy_offensive_tool_keyword = /\/pspy\/pspy\.go/
                        $string14_pspy_offensive_tool_keyword = "/pspy32"
                        $string15_pspy_offensive_tool_keyword = "/pspy64"
                        $string16_pspy_offensive_tool_keyword = /\/psscanner\.go/
                        $string17_pspy_offensive_tool_keyword = /\/psscanner\/psscanner\.go/
                        $string18_pspy_offensive_tool_keyword = /\[\+\]\sDropping\sinto\sshell/
                        $string19_pspy_offensive_tool_keyword = /\[\+\]\sStarting\spspy\snow/
                        $string20_pspy_offensive_tool_keyword = /\\pspy\\pspy\.go/
                        $string21_pspy_offensive_tool_keyword = /\\psscanner\\psscanner\.go/
                        $string22_pspy_offensive_tool_keyword = "3d770299898ab069e0a7f139ed0659991feeb17f73e55b398bf982932c200ef9"
                        $string23_pspy_offensive_tool_keyword = /Complete\slog\sof\spspy\s\(may\scontain\scommands\srun\sin\sthis\stest\)\:/
                        $string24_pspy_offensive_tool_keyword = "docker run -it --rm local/pspy"
                        $string25_pspy_offensive_tool_keyword = "DominicBreuker/pspy"
                        $string26_pspy_offensive_tool_keyword = "DominicBreuker/pspy"
                        $string27_pspy_offensive_tool_keyword = "pspy - version: "
                        $string28_pspy_offensive_tool_keyword = /pspy.{0,100}psscanner/
                        $string29_pspy_offensive_tool_keyword = "pspy32 -"
                        $string30_pspy_offensive_tool_keyword = "pspy64 -"
                        $string31_pspy_offensive_tool_keyword = "pspy64 -p"
                        $string32_pspy_offensive_tool_keyword = "pspy64 -r "
                        $string33_pspy_offensive_tool_keyword = "pspy-build:latest"
                        $string34_pspy_offensive_tool_keyword = "pspy-development:latest"
                        $string35_pspy_offensive_tool_keyword = "pspy-example:latest"
                        $string36_pspy_offensive_tool_keyword = "pspy-master"
                        $string37_pspy_offensive_tool_keyword = "pspy-testing:latest"
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