rule TTP_XOR_QUAD_CurrentVersionRun_4147 {
  strings:
    $key_4147 = { 12 28 [2] 36 26 [2] 1d 0a [2] 33 28 [2] 27 33 [2] 28 29 [2] 36 34 [2] 34 35 [2] 2f 33 [2] 33 34 [2] 2f 1b }

  condition:
    any of them
}