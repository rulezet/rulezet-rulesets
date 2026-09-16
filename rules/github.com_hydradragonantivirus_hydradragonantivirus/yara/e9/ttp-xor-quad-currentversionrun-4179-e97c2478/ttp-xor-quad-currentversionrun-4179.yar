rule TTP_XOR_QUAD_CurrentVersionRun_4179 {
  strings:
    $key_4179 = { 12 16 [2] 36 18 [2] 1d 34 [2] 33 16 [2] 27 0d [2] 28 17 [2] 36 0a [2] 34 0b [2] 2f 0d [2] 33 0a [2] 2f 25 }

  condition:
    any of them
}