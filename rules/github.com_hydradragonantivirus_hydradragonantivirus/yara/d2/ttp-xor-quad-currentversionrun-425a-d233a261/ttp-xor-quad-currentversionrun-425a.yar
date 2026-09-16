rule TTP_XOR_QUAD_CurrentVersionRun_425a {
  strings:
    $key_425a = { 11 35 [2] 35 3b [2] 1e 17 [2] 30 35 [2] 24 2e [2] 2b 34 [2] 35 29 [2] 37 28 [2] 2c 2e [2] 30 29 [2] 2c 06 }

  condition:
    any of them
}