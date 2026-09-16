rule TTP_XOR_QUAD_CurrentVersionRun_7a5c {
  strings:
    $key_7a5c = { 29 33 [2] 0d 3d [2] 26 11 [2] 08 33 [2] 1c 28 [2] 13 32 [2] 0d 2f [2] 0f 2e [2] 14 28 [2] 08 2f [2] 14 00 }

  condition:
    any of them
}