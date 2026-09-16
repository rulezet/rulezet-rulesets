rule TTP_XOR_QUAD_CurrentVersionRun_565c {
  strings:
    $key_565c = { 05 33 [2] 21 3d [2] 0a 11 [2] 24 33 [2] 30 28 [2] 3f 32 [2] 21 2f [2] 23 2e [2] 38 28 [2] 24 2f [2] 38 00 }

  condition:
    any of them
}