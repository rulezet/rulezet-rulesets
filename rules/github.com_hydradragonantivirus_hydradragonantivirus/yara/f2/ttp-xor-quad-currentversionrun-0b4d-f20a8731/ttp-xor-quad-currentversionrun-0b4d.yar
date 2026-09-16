rule TTP_XOR_QUAD_CurrentVersionRun_0b4d {
  strings:
    $key_0b4d = { 58 22 [2] 7c 2c [2] 57 00 [2] 79 22 [2] 6d 39 [2] 62 23 [2] 7c 3e [2] 7e 3f [2] 65 39 [2] 79 3e [2] 65 11 }

  condition:
    any of them
}