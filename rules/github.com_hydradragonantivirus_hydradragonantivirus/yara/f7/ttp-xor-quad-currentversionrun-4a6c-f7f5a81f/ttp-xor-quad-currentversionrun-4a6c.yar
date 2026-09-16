rule TTP_XOR_QUAD_CurrentVersionRun_4a6c {
  strings:
    $key_4a6c = { 19 03 [2] 3d 0d [2] 16 21 [2] 38 03 [2] 2c 18 [2] 23 02 [2] 3d 1f [2] 3f 1e [2] 24 18 [2] 38 1f [2] 24 30 }

  condition:
    any of them
}