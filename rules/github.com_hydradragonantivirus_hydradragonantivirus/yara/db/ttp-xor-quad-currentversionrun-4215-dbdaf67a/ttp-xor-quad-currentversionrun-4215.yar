rule TTP_XOR_QUAD_CurrentVersionRun_4215 {
  strings:
    $key_4215 = { 11 7a [2] 35 74 [2] 1e 58 [2] 30 7a [2] 24 61 [2] 2b 7b [2] 35 66 [2] 37 67 [2] 2c 61 [2] 30 66 [2] 2c 49 }

  condition:
    any of them
}