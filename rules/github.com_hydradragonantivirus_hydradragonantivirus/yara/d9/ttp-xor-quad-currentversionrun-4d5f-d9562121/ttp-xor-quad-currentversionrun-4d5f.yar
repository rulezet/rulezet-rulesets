rule TTP_XOR_QUAD_CurrentVersionRun_4d5f {
  strings:
    $key_4d5f = { 1e 30 [2] 3a 3e [2] 11 12 [2] 3f 30 [2] 2b 2b [2] 24 31 [2] 3a 2c [2] 38 2d [2] 23 2b [2] 3f 2c [2] 23 03 }

  condition:
    any of them
}