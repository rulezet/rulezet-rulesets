rule TTP_XOR_QUAD_CurrentVersionRun_cf06 {
  strings:
    $key_cf06 = { 9c 69 [2] b8 67 [2] 93 4b [2] bd 69 [2] a9 72 [2] a6 68 [2] b8 75 [2] ba 74 [2] a1 72 [2] bd 75 [2] a1 5a }

  condition:
    any of them
}