rule TTP_XOR_QUAD_CurrentVersionRun_4467 {
  strings:
    $key_4467 = { 17 08 [2] 33 06 [2] 18 2a [2] 36 08 [2] 22 13 [2] 2d 09 [2] 33 14 [2] 31 15 [2] 2a 13 [2] 36 14 [2] 2a 3b }

  condition:
    any of them
}