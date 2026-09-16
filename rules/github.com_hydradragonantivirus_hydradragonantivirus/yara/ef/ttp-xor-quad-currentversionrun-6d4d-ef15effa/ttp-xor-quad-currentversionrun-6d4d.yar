rule TTP_XOR_QUAD_CurrentVersionRun_6d4d {
  strings:
    $key_6d4d = { 3e 22 [2] 1a 2c [2] 31 00 [2] 1f 22 [2] 0b 39 [2] 04 23 [2] 1a 3e [2] 18 3f [2] 03 39 [2] 1f 3e [2] 03 11 }

  condition:
    any of them
}