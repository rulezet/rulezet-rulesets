rule TTP_XOR_QUAD_CurrentVersionRun_1a5c {
  strings:
    $key_1a5c = { 49 33 [2] 6d 3d [2] 46 11 [2] 68 33 [2] 7c 28 [2] 73 32 [2] 6d 2f [2] 6f 2e [2] 74 28 [2] 68 2f [2] 74 00 }

  condition:
    any of them
}