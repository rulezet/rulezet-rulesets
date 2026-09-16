rule TTP_XOR_QUAD_CurrentVersionRun_524d {
  strings:
    $key_524d = { 01 22 [2] 25 2c [2] 0e 00 [2] 20 22 [2] 34 39 [2] 3b 23 [2] 25 3e [2] 27 3f [2] 3c 39 [2] 20 3e [2] 3c 11 }

  condition:
    any of them
}