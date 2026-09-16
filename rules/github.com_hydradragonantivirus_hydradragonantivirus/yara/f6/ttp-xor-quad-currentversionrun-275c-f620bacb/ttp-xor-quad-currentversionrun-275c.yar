rule TTP_XOR_QUAD_CurrentVersionRun_275c {
  strings:
    $key_275c = { 74 33 [2] 50 3d [2] 7b 11 [2] 55 33 [2] 41 28 [2] 4e 32 [2] 50 2f [2] 52 2e [2] 49 28 [2] 55 2f [2] 49 00 }

  condition:
    any of them
}