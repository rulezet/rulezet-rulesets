rule TTP_XOR_QUAD_CurrentVersionRun_0d57 {
  strings:
    $key_0d57 = { 5e 38 [2] 7a 36 [2] 51 1a [2] 7f 38 [2] 6b 23 [2] 64 39 [2] 7a 24 [2] 78 25 [2] 63 23 [2] 7f 24 [2] 63 0b }

  condition:
    any of them
}