rule TTP_XOR_QUAD_CurrentVersionRun_cf36 {
  strings:
    $key_cf36 = { 9c 59 [2] b8 57 [2] 93 7b [2] bd 59 [2] a9 42 [2] a6 58 [2] b8 45 [2] ba 44 [2] a1 42 [2] bd 45 [2] a1 6a }

  condition:
    any of them
}