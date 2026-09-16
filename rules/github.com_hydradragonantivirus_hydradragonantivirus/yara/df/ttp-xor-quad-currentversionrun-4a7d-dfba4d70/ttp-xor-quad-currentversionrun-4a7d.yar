rule TTP_XOR_QUAD_CurrentVersionRun_4a7d {
  strings:
    $key_4a7d = { 19 12 [2] 3d 1c [2] 16 30 [2] 38 12 [2] 2c 09 [2] 23 13 [2] 3d 0e [2] 3f 0f [2] 24 09 [2] 38 0e [2] 24 21 }

  condition:
    any of them
}