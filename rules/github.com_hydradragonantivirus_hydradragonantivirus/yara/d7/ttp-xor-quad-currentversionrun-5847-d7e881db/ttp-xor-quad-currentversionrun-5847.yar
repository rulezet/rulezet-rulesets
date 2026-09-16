rule TTP_XOR_QUAD_CurrentVersionRun_5847 {
  strings:
    $key_5847 = { 0b 28 [2] 2f 26 [2] 04 0a [2] 2a 28 [2] 3e 33 [2] 31 29 [2] 2f 34 [2] 2d 35 [2] 36 33 [2] 2a 34 [2] 36 1b }

  condition:
    any of them
}