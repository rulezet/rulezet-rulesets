rule TTP_XOR_QUAD_CurrentVersionRun_4a5a {
  strings:
    $key_4a5a = { 19 35 [2] 3d 3b [2] 16 17 [2] 38 35 [2] 2c 2e [2] 23 34 [2] 3d 29 [2] 3f 28 [2] 24 2e [2] 38 29 [2] 24 06 }

  condition:
    any of them
}