rule TTP_XOR_QUAD_CurrentVersionRun_4747 {
  strings:
    $key_4747 = { 14 28 [2] 30 26 [2] 1b 0a [2] 35 28 [2] 21 33 [2] 2e 29 [2] 30 34 [2] 32 35 [2] 29 33 [2] 35 34 [2] 29 1b }

  condition:
    any of them
}