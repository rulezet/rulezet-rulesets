rule TTP_XOR_QUAD_CurrentVersionRun_645c {
  strings:
    $key_645c = { 37 33 [2] 13 3d [2] 38 11 [2] 16 33 [2] 02 28 [2] 0d 32 [2] 13 2f [2] 11 2e [2] 0a 28 [2] 16 2f [2] 0a 00 }

  condition:
    any of them
}