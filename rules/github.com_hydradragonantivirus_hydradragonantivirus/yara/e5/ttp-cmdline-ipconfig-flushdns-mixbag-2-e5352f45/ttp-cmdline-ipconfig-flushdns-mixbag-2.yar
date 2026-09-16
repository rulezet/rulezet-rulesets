rule ttp_cmdline_ipconfig_flushdns_mixbag_2 {
  meta:
    author = "stvemillertime"
    desc   = "Looks for suspicious cmdline string in a PE"
    ref    = "884c15502dbd6fe6dd4fca322904a38bce117ab6ed102ab2da84dfb4064c3e44"

  strings:
    $FLUSHDNS_flipflop            = "LFSUDHSN" nocase
    $FLUSHDNS_reverse             = "SNDHSULF" nocase
    $FLUSHDNS_hex_enc_str         = "464c555348444e53" nocase
    $FLUSHDNS_decimal             = "70 76 85 83 72 68 78 83" nocase
    $FLUSHDNS_stackpush           = "hHDNShFLUS" nocase
    $FLUSHDNS_stackpushnull       = "hHDNS\x00hFLUS" nocase
    $FLUSHDNS_stackpushdoublenull = "hHDNS\x00\x00hFLUS" nocase
    $FLUSHDNS_hex_movebp          = { c6 45 ?? 46 c6 45 ?? 4c c6 45 ?? 55 c6 45 ?? 53 c6 45 ?? 48 c6 45 ?? 44 c6 45 ?? 4e c6 45 ?? 53 }
    $FLUSHDNS_rot13               = "SYHFUQAF" nocase
    $z2                           = { 69 00 70 00 63 00 6F 00 6E 00 66 00 69 00 67 00 2E 00 65 00 78 00 65 00 00 00 00 }      $z3                           = { 4E 00 65 00 74 00 45 00 76 00 65 00 6E 00 74 00 2E 00 44 00 6C 00 6C 00 00 00 00 00 }      $z4                           = "FlushDnsPolicyUnreachableStatus"
    $z5                           = "flushdns</userInput>"

  condition:
    uint16be(0) == 0x4d5a
    and any of ($FLUSHDNS*)
    and not any of ($z*)
}