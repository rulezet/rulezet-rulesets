rule TTP_XOR_QUAD_CurrentVersionRun_3a5c {
  strings:
    $key_3a5c = { 69 33 [2] 4d 3d [2] 66 11 [2] 48 33 [2] 5c 28 [2] 53 32 [2] 4d 2f [2] 4f 2e [2] 54 28 [2] 48 2f [2] 54 00 }

  condition:
    any of them
}