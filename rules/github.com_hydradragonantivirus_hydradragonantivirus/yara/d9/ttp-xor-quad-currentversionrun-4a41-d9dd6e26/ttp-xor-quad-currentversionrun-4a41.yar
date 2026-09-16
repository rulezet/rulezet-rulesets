rule TTP_XOR_QUAD_CurrentVersionRun_4a41 {
  strings:
    $key_4a41 = { 19 2e [2] 3d 20 [2] 16 0c [2] 38 2e [2] 2c 35 [2] 23 2f [2] 3d 32 [2] 3f 33 [2] 24 35 [2] 38 32 [2] 24 1d }

  condition:
    any of them
}