rule TTP_XOR_QUAD_CurrentVersionRun_42f9 {
  strings:
    $key_42f9 = { 11 96 [2] 35 98 [2] 1e b4 [2] 30 96 [2] 24 8d [2] 2b 97 [2] 35 8a [2] 37 8b [2] 2c 8d [2] 30 8a [2] 2c a5 }

  condition:
    any of them
}