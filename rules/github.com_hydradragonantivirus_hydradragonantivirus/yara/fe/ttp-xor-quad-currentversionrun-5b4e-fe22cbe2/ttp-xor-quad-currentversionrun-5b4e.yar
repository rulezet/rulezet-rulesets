rule TTP_XOR_QUAD_CurrentVersionRun_5b4e {
  strings:
    $key_5b4e = { 08 21 [2] 2c 2f [2] 07 03 [2] 29 21 [2] 3d 3a [2] 32 20 [2] 2c 3d [2] 2e 3c [2] 35 3a [2] 29 3d [2] 35 12 }

  condition:
    any of them
}