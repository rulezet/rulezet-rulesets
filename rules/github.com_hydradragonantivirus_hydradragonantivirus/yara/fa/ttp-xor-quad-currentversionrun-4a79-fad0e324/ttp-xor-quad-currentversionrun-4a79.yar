rule TTP_XOR_QUAD_CurrentVersionRun_4a79 {
  strings:
    $key_4a79 = { 19 16 [2] 3d 18 [2] 16 34 [2] 38 16 [2] 2c 0d [2] 23 17 [2] 3d 0a [2] 3f 0b [2] 24 0d [2] 38 0a [2] 24 25 }

  condition:
    any of them
}