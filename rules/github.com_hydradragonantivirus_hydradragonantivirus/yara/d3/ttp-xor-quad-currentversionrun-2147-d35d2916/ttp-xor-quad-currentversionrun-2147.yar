rule TTP_XOR_QUAD_CurrentVersionRun_2147 {
  strings:
    $key_2147 = { 72 28 [2] 56 26 [2] 7d 0a [2] 53 28 [2] 47 33 [2] 48 29 [2] 56 34 [2] 54 35 [2] 4f 33 [2] 53 34 [2] 4f 1b }

  condition:
    any of them
}