rule TTP_XOR_QUAD_CurrentVersionRun_585c {
  strings:
    $key_585c = { 0b 33 [2] 2f 3d [2] 04 11 [2] 2a 33 [2] 3e 28 [2] 31 32 [2] 2f 2f [2] 2d 2e [2] 36 28 [2] 2a 2f [2] 36 00 }

  condition:
    any of them
}