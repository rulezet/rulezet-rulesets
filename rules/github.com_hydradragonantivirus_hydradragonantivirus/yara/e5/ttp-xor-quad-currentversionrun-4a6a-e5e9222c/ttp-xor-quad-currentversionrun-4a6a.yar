rule TTP_XOR_QUAD_CurrentVersionRun_4a6a {
  strings:
    $key_4a6a = { 19 05 [2] 3d 0b [2] 16 27 [2] 38 05 [2] 2c 1e [2] 23 04 [2] 3d 19 [2] 3f 18 [2] 24 1e [2] 38 19 [2] 24 36 }

  condition:
    any of them
}