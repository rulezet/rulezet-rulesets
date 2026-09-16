rule TTP_XOR_QUAD_CurrentVersionRun_4047 {
  strings:
    $key_4047 = { 13 28 [2] 37 26 [2] 1c 0a [2] 32 28 [2] 26 33 [2] 29 29 [2] 37 34 [2] 35 35 [2] 2e 33 [2] 32 34 [2] 2e 1b }

  condition:
    any of them
}