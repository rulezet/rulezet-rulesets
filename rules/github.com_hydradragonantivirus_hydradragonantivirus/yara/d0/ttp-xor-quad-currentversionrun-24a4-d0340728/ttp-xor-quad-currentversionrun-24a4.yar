rule TTP_XOR_QUAD_CurrentVersionRun_24a4 {
  strings:
    $key_24a4 = { 77 cb [2] 53 c5 [2] 78 e9 [2] 56 cb [2] 42 d0 [2] 4d ca [2] 53 d7 [2] 51 d6 [2] 4a d0 [2] 56 d7 [2] 4a f8 }

  condition:
    any of them
}