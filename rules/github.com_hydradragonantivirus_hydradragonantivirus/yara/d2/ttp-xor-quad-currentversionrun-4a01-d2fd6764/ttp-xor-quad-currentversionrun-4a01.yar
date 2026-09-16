rule TTP_XOR_QUAD_CurrentVersionRun_4a01 {
  strings:
    $key_4a01 = { 19 6e [2] 3d 60 [2] 16 4c [2] 38 6e [2] 2c 75 [2] 23 6f [2] 3d 72 [2] 3f 73 [2] 24 75 [2] 38 72 [2] 24 5d }

  condition:
    any of them
}