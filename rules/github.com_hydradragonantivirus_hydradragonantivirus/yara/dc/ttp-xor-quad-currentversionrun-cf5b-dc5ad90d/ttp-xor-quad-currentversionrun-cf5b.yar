rule TTP_XOR_QUAD_CurrentVersionRun_cf5b {
  strings:
    $key_cf5b = { 9c 34 [2] b8 3a [2] 93 16 [2] bd 34 [2] a9 2f [2] a6 35 [2] b8 28 [2] ba 29 [2] a1 2f [2] bd 28 [2] a1 07 }

  condition:
    any of them
}