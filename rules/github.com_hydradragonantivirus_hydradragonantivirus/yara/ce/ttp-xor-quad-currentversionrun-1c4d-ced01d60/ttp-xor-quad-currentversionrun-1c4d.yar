rule TTP_XOR_QUAD_CurrentVersionRun_1c4d {
  strings:
    $key_1c4d = { 4f 22 [2] 6b 2c [2] 40 00 [2] 6e 22 [2] 7a 39 [2] 75 23 [2] 6b 3e [2] 69 3f [2] 72 39 [2] 6e 3e [2] 72 11 }

  condition:
    any of them
}