rule TTP_XOR_QUAD_CurrentVersionRun_6e42 {
  strings:
    $key_6e42 = { 3d 2d [2] 19 23 [2] 32 0f [2] 1c 2d [2] 08 36 [2] 07 2c [2] 19 31 [2] 1b 30 [2] 00 36 [2] 1c 31 [2] 00 1e }

  condition:
    any of them
}