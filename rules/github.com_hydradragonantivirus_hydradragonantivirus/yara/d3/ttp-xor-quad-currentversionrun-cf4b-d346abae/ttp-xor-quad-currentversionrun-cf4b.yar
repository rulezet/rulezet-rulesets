rule TTP_XOR_QUAD_CurrentVersionRun_cf4b {
  strings:
    $key_cf4b = { 9c 24 [2] b8 2a [2] 93 06 [2] bd 24 [2] a9 3f [2] a6 25 [2] b8 38 [2] ba 39 [2] a1 3f [2] bd 38 [2] a1 17 }

  condition:
    any of them
}