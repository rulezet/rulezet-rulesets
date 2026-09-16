rule TTP_XOR_QUAD_CurrentVersionRun_7b4d {
  strings:
    $key_7b4d = { 28 22 [2] 0c 2c [2] 27 00 [2] 09 22 [2] 1d 39 [2] 12 23 [2] 0c 3e [2] 0e 3f [2] 15 39 [2] 09 3e [2] 15 11 }

  condition:
    any of them
}