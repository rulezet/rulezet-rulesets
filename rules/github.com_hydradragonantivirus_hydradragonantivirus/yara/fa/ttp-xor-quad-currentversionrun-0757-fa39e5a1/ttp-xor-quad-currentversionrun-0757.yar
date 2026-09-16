rule TTP_XOR_QUAD_CurrentVersionRun_0757 {
  strings:
    $key_0757 = { 54 38 [2] 70 36 [2] 5b 1a [2] 75 38 [2] 61 23 [2] 6e 39 [2] 70 24 [2] 72 25 [2] 69 23 [2] 75 24 [2] 69 0b }

  condition:
    any of them
}