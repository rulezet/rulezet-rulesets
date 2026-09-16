rule TTP_XOR_QUAD_CurrentVersionRun_4a0c {
  strings:
    $key_4a0c = { 19 63 [2] 3d 6d [2] 16 41 [2] 38 63 [2] 2c 78 [2] 23 62 [2] 3d 7f [2] 3f 7e [2] 24 78 [2] 38 7f [2] 24 50 }

  condition:
    any of them
}