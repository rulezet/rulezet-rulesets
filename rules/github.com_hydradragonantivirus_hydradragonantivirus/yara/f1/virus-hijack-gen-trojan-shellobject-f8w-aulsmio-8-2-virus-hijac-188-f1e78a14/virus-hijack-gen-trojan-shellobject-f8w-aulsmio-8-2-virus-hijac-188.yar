rule _Virus_Hijack_Gen_Trojan_ShellObject_f8W_auLSMIo_8_2_Virus_Hijac_188 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.f8W@auLSMIo_8_2.vir, Virus.Hijack_Trojan.GenericKDZ.105924_238_1.vir, Virus.Infector_Gen.Trojan.Malware.Lq3@aunLb5ni_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "701dc79cdc00d940b90dad844b2be65c31d61e14d204b9270431f06e89d8ad41"
    hash2       = "38d57b02dd6a282748156e58d28a30953228acd71fa035f3b81414ba058074fb"
    hash3       = "a316d2edeae0147ec627ae5d020170e6666f5b8f454f703c611cf00983ae1deb"

  strings:
    $s1 = "  -d, --dump-only      just list packages, do not verify (with -c)" fullword ascii
    $s2 = "  search all official Cygwin packages use -p instead.  The -p REGEXP matches" fullword ascii
    $s3 = "  package names, descriptions, and names of files/paths within all packages." fullword ascii
    $s4 = "  -l, --list-package   list contents of PACKAGE (or all packages if none given)" fullword ascii
    $s5 = "       with another command, otherwise print this help" fullword ascii
    $s6 = "2016 Preview" fullword ascii
    $s7 = "  -f, --find-package   find the package to which FILE belongs" fullword ascii
    $s8 = "       Delete installation keys of old, now unused" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (all of them)
    ) or (all of them)
}