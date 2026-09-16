rule TTP_XOR_QUAD_CurrentVersionRun_e159 {
  strings:
    $key_e159 = { b2 36 [2] 96 38 [2] bd 14 [2] 93 36 [2] 87 2d [2] 88 37 [2] 96 2a [2] 94 2b [2] 8f 2d [2] 93 2a [2] 8f 05 }

  condition:
    any of them
}