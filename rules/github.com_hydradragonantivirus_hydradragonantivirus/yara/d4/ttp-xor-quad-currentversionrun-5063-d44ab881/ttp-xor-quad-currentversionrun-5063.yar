rule TTP_XOR_QUAD_CurrentVersionRun_5063 {
  strings:
    $key_5063 = { 03 0c [2] 27 02 [2] 0c 2e [2] 22 0c [2] 36 17 [2] 39 0d [2] 27 10 [2] 25 11 [2] 3e 17 [2] 22 10 [2] 3e 3f }

  condition:
    any of them
}