rule TTP_XOR_QUAD_CurrentVersionRun_4c56 {
  strings:
    $key_4c56 = { 1f 39 [2] 3b 37 [2] 10 1b [2] 3e 39 [2] 2a 22 [2] 25 38 [2] 3b 25 [2] 39 24 [2] 22 22 [2] 3e 25 [2] 22 0a }

  condition:
    any of them
}