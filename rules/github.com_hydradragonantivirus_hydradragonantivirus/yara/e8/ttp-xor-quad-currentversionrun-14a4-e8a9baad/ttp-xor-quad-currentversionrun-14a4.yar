rule TTP_XOR_QUAD_CurrentVersionRun_14a4 {
  strings:
    $key_14a4 = { 47 cb [2] 63 c5 [2] 48 e9 [2] 66 cb [2] 72 d0 [2] 7d ca [2] 63 d7 [2] 61 d6 [2] 7a d0 [2] 66 d7 [2] 7a f8 }

  condition:
    any of them
}