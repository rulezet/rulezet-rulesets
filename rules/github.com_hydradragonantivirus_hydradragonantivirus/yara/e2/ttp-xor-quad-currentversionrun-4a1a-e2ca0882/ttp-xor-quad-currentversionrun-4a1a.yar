rule TTP_XOR_QUAD_CurrentVersionRun_4a1a {
  strings:
    $key_4a1a = { 19 75 [2] 3d 7b [2] 16 57 [2] 38 75 [2] 2c 6e [2] 23 74 [2] 3d 69 [2] 3f 68 [2] 24 6e [2] 38 69 [2] 24 46 }

  condition:
    any of them
}