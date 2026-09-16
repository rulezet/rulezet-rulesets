rule TTP_XOR_QUAD_CurrentVersionRun_4c5c {
  strings:
    $key_4c5c = { 1f 33 [2] 3b 3d [2] 10 11 [2] 3e 33 [2] 2a 28 [2] 25 32 [2] 3b 2f [2] 39 2e [2] 22 28 [2] 3e 2f [2] 22 00 }

  condition:
    any of them
}