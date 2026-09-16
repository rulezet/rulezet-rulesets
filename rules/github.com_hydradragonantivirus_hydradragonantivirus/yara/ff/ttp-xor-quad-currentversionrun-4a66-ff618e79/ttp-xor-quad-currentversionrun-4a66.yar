rule TTP_XOR_QUAD_CurrentVersionRun_4a66 {
  strings:
    $key_4a66 = { 19 09 [2] 3d 07 [2] 16 2b [2] 38 09 [2] 2c 12 [2] 23 08 [2] 3d 15 [2] 3f 14 [2] 24 12 [2] 38 15 [2] 24 3a }

  condition:
    any of them
}