rule TTP_XOR_QUAD_CurrentVersionRun_03b6 {
  strings:
    $key_03b6 = { 50 d9 [2] 74 d7 [2] 5f fb [2] 71 d9 [2] 65 c2 [2] 6a d8 [2] 74 c5 [2] 76 c4 [2] 6d c2 [2] 71 c5 [2] 6d ea }

  condition:
    any of them
}