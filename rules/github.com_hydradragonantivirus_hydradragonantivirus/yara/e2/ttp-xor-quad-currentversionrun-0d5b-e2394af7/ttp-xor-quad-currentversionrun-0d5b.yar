rule TTP_XOR_QUAD_CurrentVersionRun_0d5b {
  strings:
    $key_0d5b = { 5e 34 [2] 7a 3a [2] 51 16 [2] 7f 34 [2] 6b 2f [2] 64 35 [2] 7a 28 [2] 78 29 [2] 63 2f [2] 7f 28 [2] 63 07 }

  condition:
    any of them
}