rule TTP_XOR_QUAD_CurrentVersionRun_701b {
  strings:
    $key_701b = { 23 74 [2] 07 7a [2] 2c 56 [2] 02 74 [2] 16 6f [2] 19 75 [2] 07 68 [2] 05 69 [2] 1e 6f [2] 02 68 [2] 1e 47 }

  condition:
    any of them
}