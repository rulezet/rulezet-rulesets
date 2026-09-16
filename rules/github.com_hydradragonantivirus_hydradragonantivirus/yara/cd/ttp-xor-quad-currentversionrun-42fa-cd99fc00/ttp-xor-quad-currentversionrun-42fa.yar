rule TTP_XOR_QUAD_CurrentVersionRun_42fa {
  strings:
    $key_42fa = { 11 95 [2] 35 9b [2] 1e b7 [2] 30 95 [2] 24 8e [2] 2b 94 [2] 35 89 [2] 37 88 [2] 2c 8e [2] 30 89 [2] 2c a6 }

  condition:
    any of them
}