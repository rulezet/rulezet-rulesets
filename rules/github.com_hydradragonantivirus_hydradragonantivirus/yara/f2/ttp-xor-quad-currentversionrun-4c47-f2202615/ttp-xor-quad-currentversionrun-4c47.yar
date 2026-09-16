rule TTP_XOR_QUAD_CurrentVersionRun_4c47 {
  strings:
    $key_4c47 = { 1f 28 [2] 3b 26 [2] 10 0a [2] 3e 28 [2] 2a 33 [2] 25 29 [2] 3b 34 [2] 39 35 [2] 22 33 [2] 3e 34 [2] 22 1b }

  condition:
    any of them
}