rule TTP_XOR_QUAD_CurrentVersionRun_6f4d {
  strings:
    $key_6f4d = { 3c 22 [2] 18 2c [2] 33 00 [2] 1d 22 [2] 09 39 [2] 06 23 [2] 18 3e [2] 1a 3f [2] 01 39 [2] 1d 3e [2] 01 11 }

  condition:
    any of them
}