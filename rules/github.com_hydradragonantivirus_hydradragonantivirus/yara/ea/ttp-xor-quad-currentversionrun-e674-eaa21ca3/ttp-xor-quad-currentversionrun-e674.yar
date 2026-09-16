rule TTP_XOR_QUAD_CurrentVersionRun_e674 {
  strings:
    $key_e674 = { b5 1b [2] 91 15 [2] ba 39 [2] 94 1b [2] 80 00 [2] 8f 1a [2] 91 07 [2] 93 06 [2] 88 00 [2] 94 07 [2] 88 28 }

  condition:
    any of them
}