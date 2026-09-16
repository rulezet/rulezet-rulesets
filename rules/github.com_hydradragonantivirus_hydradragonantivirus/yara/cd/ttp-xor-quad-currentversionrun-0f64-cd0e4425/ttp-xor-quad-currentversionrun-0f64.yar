rule TTP_XOR_QUAD_CurrentVersionRun_0f64 {
  strings:
    $key_0f64 = { 5c 0b [2] 78 05 [2] 53 29 [2] 7d 0b [2] 69 10 [2] 66 0a [2] 78 17 [2] 7a 16 [2] 61 10 [2] 7d 17 [2] 61 38 }

  condition:
    any of them
}