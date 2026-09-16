rule TTP_XOR_QUAD_CurrentVersionRun_7942 {
  strings:
    $key_7942 = { 2a 2d [2] 0e 23 [2] 25 0f [2] 0b 2d [2] 1f 36 [2] 10 2c [2] 0e 31 [2] 0c 30 [2] 17 36 [2] 0b 31 [2] 17 1e }

  condition:
    any of them
}