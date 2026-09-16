rule TTP_XOR_QUAD_CurrentVersionRun_4a6d {
  strings:
    $key_4a6d = { 19 02 [2] 3d 0c [2] 16 20 [2] 38 02 [2] 2c 19 [2] 23 03 [2] 3d 1e [2] 3f 1f [2] 24 19 [2] 38 1e [2] 24 31 }

  condition:
    any of them
}