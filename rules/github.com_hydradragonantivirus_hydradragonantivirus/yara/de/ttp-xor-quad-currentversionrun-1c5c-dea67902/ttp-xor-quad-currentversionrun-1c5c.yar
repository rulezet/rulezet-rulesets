rule TTP_XOR_QUAD_CurrentVersionRun_1c5c {
  strings:
    $key_1c5c = { 4f 33 [2] 6b 3d [2] 40 11 [2] 6e 33 [2] 7a 28 [2] 75 32 [2] 6b 2f [2] 69 2e [2] 72 28 [2] 6e 2f [2] 72 00 }

  condition:
    any of them
}