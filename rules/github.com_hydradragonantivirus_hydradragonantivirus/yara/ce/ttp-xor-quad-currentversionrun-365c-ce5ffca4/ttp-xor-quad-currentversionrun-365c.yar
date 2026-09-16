rule TTP_XOR_QUAD_CurrentVersionRun_365c {
  strings:
    $key_365c = { 65 33 [2] 41 3d [2] 6a 11 [2] 44 33 [2] 50 28 [2] 5f 32 [2] 41 2f [2] 43 2e [2] 58 28 [2] 44 2f [2] 58 00 }

  condition:
    any of them
}