rule TTP_XOR_QUAD_CurrentVersionRun_685b {
  strings:
    $key_685b = { 3b 34 [2] 1f 3a [2] 34 16 [2] 1a 34 [2] 0e 2f [2] 01 35 [2] 1f 28 [2] 1d 29 [2] 06 2f [2] 1a 28 [2] 06 07 }

  condition:
    any of them
}