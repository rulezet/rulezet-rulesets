rule TTP_XOR_QUAD_CurrentVersionRun_0c5c {
  strings:
    $key_0c5c = { 5f 33 [2] 7b 3d [2] 50 11 [2] 7e 33 [2] 6a 28 [2] 65 32 [2] 7b 2f [2] 79 2e [2] 62 28 [2] 7e 2f [2] 62 00 }

  condition:
    any of them
}