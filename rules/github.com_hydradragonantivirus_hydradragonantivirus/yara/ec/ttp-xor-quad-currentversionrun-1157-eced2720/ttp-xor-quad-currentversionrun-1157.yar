rule TTP_XOR_QUAD_CurrentVersionRun_1157 {
  strings:
    $key_1157 = { 42 38 [2] 66 36 [2] 4d 1a [2] 63 38 [2] 77 23 [2] 78 39 [2] 66 24 [2] 64 25 [2] 7f 23 [2] 63 24 [2] 7f 0b }

  condition:
    any of them
}