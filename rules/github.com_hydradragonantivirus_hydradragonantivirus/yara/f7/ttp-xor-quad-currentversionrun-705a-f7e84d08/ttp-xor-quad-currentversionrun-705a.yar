rule TTP_XOR_QUAD_CurrentVersionRun_705a {
  strings:
    $key_705a = { 23 35 [2] 07 3b [2] 2c 17 [2] 02 35 [2] 16 2e [2] 19 34 [2] 07 29 [2] 05 28 [2] 1e 2e [2] 02 29 [2] 1e 06 }

  condition:
    any of them
}