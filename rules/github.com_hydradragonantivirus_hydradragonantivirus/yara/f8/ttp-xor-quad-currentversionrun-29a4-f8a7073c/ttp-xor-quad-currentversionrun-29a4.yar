rule TTP_XOR_QUAD_CurrentVersionRun_29a4 {
  strings:
    $key_29a4 = { 7a cb [2] 5e c5 [2] 75 e9 [2] 5b cb [2] 4f d0 [2] 40 ca [2] 5e d7 [2] 5c d6 [2] 47 d0 [2] 5b d7 [2] 47 f8 }

  condition:
    any of them
}