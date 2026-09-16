rule TTP_XOR_QUAD_CurrentVersionRun_2d5c {
  strings:
    $key_2d5c = { 7e 33 [2] 5a 3d [2] 71 11 [2] 5f 33 [2] 4b 28 [2] 44 32 [2] 5a 2f [2] 58 2e [2] 43 28 [2] 5f 2f [2] 43 00 }

  condition:
    any of them
}