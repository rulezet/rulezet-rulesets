rule TTP_XOR_QUAD_CurrentVersionRun_3467 {
  strings:
    $key_3467 = { 67 08 [2] 43 06 [2] 68 2a [2] 46 08 [2] 52 13 [2] 5d 09 [2] 43 14 [2] 41 15 [2] 5a 13 [2] 46 14 [2] 5a 3b }

  condition:
    any of them
}