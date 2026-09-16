rule TTP_XOR_QUAD_CurrentVersionRun_cab8 {
  strings:
    $key_cab8 = { 99 d7 [2] bd d9 [2] 96 f5 [2] b8 d7 [2] ac cc [2] a3 d6 [2] bd cb [2] bf ca [2] a4 cc [2] b8 cb [2] a4 e4 }

  condition:
    any of them
}