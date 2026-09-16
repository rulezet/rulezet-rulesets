rule TTP_XOR_QUAD_CurrentVersionRun_4209 {
  strings:
    $key_4209 = { 11 66 [2] 35 68 [2] 1e 44 [2] 30 66 [2] 24 7d [2] 2b 67 [2] 35 7a [2] 37 7b [2] 2c 7d [2] 30 7a [2] 2c 55 }

  condition:
    any of them
}