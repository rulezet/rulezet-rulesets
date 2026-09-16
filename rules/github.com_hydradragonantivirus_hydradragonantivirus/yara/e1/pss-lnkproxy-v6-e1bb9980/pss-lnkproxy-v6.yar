rule PSS_lnkproxy_v6 {
  meta:
    description = "PSS lnkproxy version 6.0.0 and 6.1.0"
    author      = "Geoffrey Alexander <geoff@citizenlab.ca>"
    date        = "2017-07-20"

  strings:
    $s1 = "C:\\Windows\\temp\\KB2971112.pdb"
    $s2 = "AVResourceException@exception@util@@" ascii
    $s3 = "AVLnkControllerException@LnkProxy@@" ascii
    $s4 = "AVLnkPayloadException@@" ascii
    $s5 = "AVShellLinkException@LnkProxy@@" ascii
    $s6 = "AVFileUtilitiesException@LnkProxy@@" ascii
    $s7 = "AVLnkEntryException@LnkProxy@@" ascii
    $s8 = "AVFileRollbackException@LnkProxy@@" ascii

    $str_decrypt_loop = { 8b 47 04 8b ce 83 e1 03 c1 e1 03 ba ?? ?? ?? ?? d3 ea 32 54 35 ?? 88 14 06 46 3b f3 }

  condition:
    uint16(0) == 0x5a4d and 3 of ($s*) and $str_decrypt_loop
}