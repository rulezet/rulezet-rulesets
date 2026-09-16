rule TTP_XOR_QUAD_CurrentVersionRun_604d {
  strings:
    $key_604d = { 33 22 [2] 17 2c [2] 3c 00 [2] 12 22 [2] 06 39 [2] 09 23 [2] 17 3e [2] 15 3f [2] 0e 39 [2] 12 3e [2] 0e 11 }

  condition:
    any of them
}