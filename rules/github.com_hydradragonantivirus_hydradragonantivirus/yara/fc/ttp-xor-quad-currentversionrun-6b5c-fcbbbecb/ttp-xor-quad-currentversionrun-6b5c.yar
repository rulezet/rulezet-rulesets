rule TTP_XOR_QUAD_CurrentVersionRun_6b5c {
  strings:
    $key_6b5c = { 38 33 [2] 1c 3d [2] 37 11 [2] 19 33 [2] 0d 28 [2] 02 32 [2] 1c 2f [2] 1e 2e [2] 05 28 [2] 19 2f [2] 05 00 }

  condition:
    any of them
}