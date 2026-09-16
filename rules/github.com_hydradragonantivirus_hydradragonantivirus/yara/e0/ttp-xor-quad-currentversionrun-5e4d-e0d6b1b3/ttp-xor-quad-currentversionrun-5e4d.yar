rule TTP_XOR_QUAD_CurrentVersionRun_5e4d {
  strings:
    $key_5e4d = { 0d 22 [2] 29 2c [2] 02 00 [2] 2c 22 [2] 38 39 [2] 37 23 [2] 29 3e [2] 2b 3f [2] 30 39 [2] 2c 3e [2] 30 11 }

  condition:
    any of them
}