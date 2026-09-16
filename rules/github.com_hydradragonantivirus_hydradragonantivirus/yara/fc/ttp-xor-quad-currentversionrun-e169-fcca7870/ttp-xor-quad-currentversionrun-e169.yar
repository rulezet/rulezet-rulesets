rule TTP_XOR_QUAD_CurrentVersionRun_e169 {
  strings:
    $key_e169 = { b2 06 [2] 96 08 [2] bd 24 [2] 93 06 [2] 87 1d [2] 88 07 [2] 96 1a [2] 94 1b [2] 8f 1d [2] 93 1a [2] 8f 35 }

  condition:
    any of them
}