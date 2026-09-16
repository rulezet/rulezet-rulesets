rule TTP_XOR_QUAD_CurrentVersionRun_4a4d {
  strings:
    $key_4a4d = { 19 22 [2] 3d 2c [2] 16 00 [2] 38 22 [2] 2c 39 [2] 23 23 [2] 3d 3e [2] 3f 3f [2] 24 39 [2] 38 3e [2] 24 11 }

  condition:
    any of them
}