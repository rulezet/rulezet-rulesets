rule TTP_XOR_QUAD_CurrentVersionRun_72b6 {
  strings:
    $key_72b6 = { 21 d9 [2] 05 d7 [2] 2e fb [2] 00 d9 [2] 14 c2 [2] 1b d8 [2] 05 c5 [2] 07 c4 [2] 1c c2 [2] 00 c5 [2] 1c ea }

  condition:
    any of them
}