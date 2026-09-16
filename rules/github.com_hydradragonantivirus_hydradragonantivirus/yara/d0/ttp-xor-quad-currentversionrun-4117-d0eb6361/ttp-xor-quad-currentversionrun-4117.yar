rule TTP_XOR_QUAD_CurrentVersionRun_4117 {
  strings:
    $key_4117 = { 12 78 [2] 36 76 [2] 1d 5a [2] 33 78 [2] 27 63 [2] 28 79 [2] 36 64 [2] 34 65 [2] 2f 63 [2] 33 64 [2] 2f 4b }

  condition:
    any of them
}