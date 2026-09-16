rule TTP_XOR_QUAD_CurrentVersionRun_16b7 {
  strings:
    $key_16b7 = { 45 d8 [2] 61 d6 [2] 4a fa [2] 64 d8 [2] 70 c3 [2] 7f d9 [2] 61 c4 [2] 63 c5 [2] 78 c3 [2] 64 c4 [2] 78 eb }

  condition:
    any of them
}