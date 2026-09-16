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
                        $string28 = /pspy.{0,1000}psscanner/
                        $string29 = "pspy32 -"
                        $string30 = "pspy64 -"
                        $string31 = "pspy64 -p"
                        $string32 = "pspy64 -r "
                        $string33 = "pspy-build:latest"
                        $string34 = "pspy-development:latest"
                        $string35 = "pspy-example:latest"
                        $string36 = "pspy-master"
                        $string37 = "pspy-testing:latest"

    condition:
        any of them
}