rule ttp_cmdline_ipconfig_flushdns_mixbag_3 {
  meta:
    author = "stvemillertime"
    desc   = "Looks for suspicious cmdline string in a PE"
    ref    = "884c15502dbd6fe6dd4fca322904a38bce117ab6ed102ab2da84dfb4064c3e44"

  strings:
    $FlushDns_flipflop            = "lFsuDhsn" nocase
    $FlushDns_reverse             = "snDhsulF" nocase
    $FlushDns_hex_enc_str         = "466c757368446e73" nocase
    $FlushDns_decimal             = "70 108 117 115 104 68 110 115" nocase
    $FlushDns_fallchill           = "FofhsDmh" nocase
    $FlushDns_stackpush           = "hhDnshFlus" nocase
    $FlushDns_stackpushnull       = "h\x00hDnshFlus" nocase
    $FlushDns_stackpushdoublenull = "h\x00\x00hDnshFlus" nocase
    $FlushDns_hex_movebp          = { c6 45 ?? 46 c6 45 ?? 6c c6 45 ?? 75 c6 45 ?? 73 c6 45 ?? 68 c6 45 ?? 44 c6 45 ?? 6e c6 45 ?? 73 }
    $FlushDns_rot13               = "SyhfuQaf" nocase
    $z2                           = { 69 00 70 00 63 00 6F 00 6E 00 66 00 69 00 67 00 2E 00 65 00 78 00 65 00 00 00 00 }      $z3                           = { 4E 00 65 00 74 00 45 00 76 00 65 00 6E 00 74 00 2E 00 44 00 6C 00 6C 00 00 00 00 00 }      $z4                           = "FlushDnsPolicyUnreachableStatus"
    $z5                           = "flushdns</userInput>"

  condition:
    uint16be(0) == 0x4d5a
    and any of ($FlushDns*)
    and not any of ($z*)
}