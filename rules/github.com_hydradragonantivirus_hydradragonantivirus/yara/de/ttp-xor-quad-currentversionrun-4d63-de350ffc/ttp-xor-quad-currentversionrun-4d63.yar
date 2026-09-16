rule TTP_XOR_QUAD_CurrentVersionRun_4d63 {
  strings:
    $key_4d63 = { 1e 0c [2] 3a 02 [2] 11 2e [2] 3f 0c [2] 2b 17 [2] 24 0d [2] 3a 10 [2] 38 11 [2] 23 17 [2] 3f 10 [2] 23 3f }

  condition:
    any of them
}