rule XProtect_MACOS_60a3d68 {
  meta:
    description = "MACOS.60a3d68"

  strings:
    $a  = "#!"
    $b1 = { 6f 70 65 6e 73 73 6c [1-3] 65 6e 63 }
    $b2 = "-aes-256-cbc"
    $c1 = "$O$P$E$N$S$S$L $E$N$C"
    $c2 = "-$A$E$S-256-cbc"
    $d1 = "${O}${P}${E}${N}${S}${S}${L} ${E}${N}${C}"
    $d2 = "-${A}${E}${S}-256-cbc"
    $e1 = "-base64"
    $e2 = "-a"
    $e3 = "-b${A}${S}${E}64"
    $f  = "-d"
    $g1 = "-in"
    $g2 = "-nosalt"
    $g3 = "-salt"
    $g4 = "-k"
    $g5 = "-out"
    $g6 = "-pass"
    $g7 = "-P$A$S$S"
    $g8 = "-${P}${A}${S}${S}"
    $h1 = "dd if=/dev/urandom bs=$(jot -r 1 5 15)"
    $h2 = "base64 | tr -dc 'a-zA-Z0-9'"
    $h3 = "<enc)\""
    $h4 = "Resources/enc)\""
    $h5 = "shell_exec"
    $h6 = "eval"
    $h7 = "chmod +x "
    $h8 = "subprocess.Popen"

  condition:
    $a at 0 and filesize < 5KB and (all of ($b*) or all of ($c*) or all of ($d*)) and any of ($e*) and $f and any of ($g*) and any of ($h*)
}