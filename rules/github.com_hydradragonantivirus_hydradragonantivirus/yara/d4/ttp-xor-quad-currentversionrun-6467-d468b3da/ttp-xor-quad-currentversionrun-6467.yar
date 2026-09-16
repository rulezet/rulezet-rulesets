rule TTP_XOR_QUAD_CurrentVersionRun_6467 {
  strings:
    $key_6467 = { 37 08 [2] 13 06 [2] 38 2a [2] 16 08 [2] 02 13 [2] 0d 09 [2] 13 14 [2] 11 15 [2] 0a 13 [2] 16 14 [2] 0a 3b }

  condition:
    any of them
}