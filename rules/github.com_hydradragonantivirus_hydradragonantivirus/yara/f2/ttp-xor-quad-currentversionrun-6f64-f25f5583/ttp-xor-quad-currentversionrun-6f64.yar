rule TTP_XOR_QUAD_CurrentVersionRun_6f64 {
  strings:
    $key_6f64 = { 3c 0b [2] 18 05 [2] 33 29 [2] 1d 0b [2] 09 10 [2] 06 0a [2] 18 17 [2] 1a 16 [2] 01 10 [2] 1d 17 [2] 01 38 }

  condition:
    any of them
}