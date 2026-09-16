rule TTP_XOR_QUAD_CurrentVersionRun_1f64 {
  strings:
    $key_1f64 = { 4c 0b [2] 68 05 [2] 43 29 [2] 6d 0b [2] 79 10 [2] 76 0a [2] 68 17 [2] 6a 16 [2] 71 10 [2] 6d 17 [2] 71 38 }

  condition:
    any of them
}