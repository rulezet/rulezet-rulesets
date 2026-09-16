rule TTP_XOR_QUAD_CurrentVersionRun_4c42 {
  strings:
    $key_4c42 = { 1f 2d [2] 3b 23 [2] 10 0f [2] 3e 2d [2] 2a 36 [2] 25 2c [2] 3b 31 [2] 39 30 [2] 22 36 [2] 3e 31 [2] 22 1e }

  condition:
    any of them
}