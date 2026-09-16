rule TTP_XOR_QUAD_CurrentVersionRun_794d {
  strings:
    $key_794d = { 2a 22 [2] 0e 2c [2] 25 00 [2] 0b 22 [2] 1f 39 [2] 10 23 [2] 0e 3e [2] 0c 3f [2] 17 39 [2] 0b 3e [2] 17 11 }

  condition:
    any of them
}