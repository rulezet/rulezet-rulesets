rule TTP_XOR_QUAD_CurrentVersionRun_2ba4 {
  strings:
    $key_2ba4 = { 78 cb [2] 5c c5 [2] 77 e9 [2] 59 cb [2] 4d d0 [2] 42 ca [2] 5c d7 [2] 5e d6 [2] 45 d0 [2] 59 d7 [2] 45 f8 }

  condition:
    any of them
}