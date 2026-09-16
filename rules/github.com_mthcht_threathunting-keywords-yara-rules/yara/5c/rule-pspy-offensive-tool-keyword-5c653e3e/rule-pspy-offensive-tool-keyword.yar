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
                        $string28_pspy_offensive_tool_keyword = /pspy.{0,1000}psscanner/
                        $string29_pspy_offensive_tool_keyword = "pspy32 -"
                        $string30_pspy_offensive_tool_keyword = "pspy64 -"
                        $string31_pspy_offensive_tool_keyword = "pspy64 -p"
                        $string32_pspy_offensive_tool_keyword = "pspy64 -r "
                        $string33_pspy_offensive_tool_keyword = "pspy-build:latest"
                        $string34_pspy_offensive_tool_keyword = "pspy-development:latest"
                        $string35_pspy_offensive_tool_keyword = "pspy-example:latest"
                        $string36_pspy_offensive_tool_keyword = "pspy-master"
                        $string37_pspy_offensive_tool_keyword = "pspy-testing:latest"

    condition:
        any of them
}