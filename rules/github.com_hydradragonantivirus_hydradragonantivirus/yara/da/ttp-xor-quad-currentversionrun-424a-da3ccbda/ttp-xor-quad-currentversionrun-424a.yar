rule TTP_XOR_QUAD_CurrentVersionRun_424a {
  strings:
    $key_424a = { 11 25 [2] 35 2b [2] 1e 07 [2] 30 25 [2] 24 3e [2] 2b 24 [2] 35 39 [2] 37 38 [2] 2c 3e [2] 30 39 [2] 2c 16 }

  condition:
    any of them
}