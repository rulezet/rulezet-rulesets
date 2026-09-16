rule TTP_XOR_QUAD_CurrentVersionRun_0b5c {
  strings:
    $key_0b5c = { 58 33 [2] 7c 3d [2] 57 11 [2] 79 33 [2] 6d 28 [2] 62 32 [2] 7c 2f [2] 7e 2e [2] 65 28 [2] 79 2f [2] 65 00 }

  condition:
    any of them
}