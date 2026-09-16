rule TTP_XOR_QUAD_CurrentVersionRun_02b6 {
  strings:
    $key_02b6 = { 51 d9 [2] 75 d7 [2] 5e fb [2] 70 d9 [2] 64 c2 [2] 6b d8 [2] 75 c5 [2] 77 c4 [2] 6c c2 [2] 70 c5 [2] 6c ea }

  condition:
    any of them
}