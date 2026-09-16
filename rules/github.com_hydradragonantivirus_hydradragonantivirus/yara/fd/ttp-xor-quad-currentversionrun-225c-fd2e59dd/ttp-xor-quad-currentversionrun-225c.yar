rule TTP_XOR_QUAD_CurrentVersionRun_225c {
  strings:
    $key_225c = { 71 33 [2] 55 3d [2] 7e 11 [2] 50 33 [2] 44 28 [2] 4b 32 [2] 55 2f [2] 57 2e [2] 4c 28 [2] 50 2f [2] 4c 00 }

  condition:
    any of them
}