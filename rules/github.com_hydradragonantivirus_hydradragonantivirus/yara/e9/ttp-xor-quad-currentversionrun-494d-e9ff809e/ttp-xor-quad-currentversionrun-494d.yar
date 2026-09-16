rule TTP_XOR_QUAD_CurrentVersionRun_494d {
  strings:
    $key_494d = { 1a 22 [2] 3e 2c [2] 15 00 [2] 3b 22 [2] 2f 39 [2] 20 23 [2] 3e 3e [2] 3c 3f [2] 27 39 [2] 3b 3e [2] 27 11 }

  condition:
    any of them
}