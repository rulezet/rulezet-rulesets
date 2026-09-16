rule TTP_XOR_QUAD_CurrentVersionRun_4a7c {
  strings:
    $key_4a7c = { 19 13 [2] 3d 1d [2] 16 31 [2] 38 13 [2] 2c 08 [2] 23 12 [2] 3d 0f [2] 3f 0e [2] 24 08 [2] 38 0f [2] 24 20 }

  condition:
    any of them
}