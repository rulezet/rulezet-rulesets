rule TTP_XOR_QUAD_CurrentVersionRun_4156 {
  strings:
    $key_4156 = { 12 39 [2] 36 37 [2] 1d 1b [2] 33 39 [2] 27 22 [2] 28 38 [2] 36 25 [2] 34 24 [2] 2f 22 [2] 33 25 [2] 2f 0a }

  condition:
    any of them
}