rule TTP_XOR_QUAD_CurrentVersionRun_5b4d {
  strings:
    $key_5b4d = { 08 22 [2] 2c 2c [2] 07 00 [2] 29 22 [2] 3d 39 [2] 32 23 [2] 2c 3e [2] 2e 3f [2] 35 39 [2] 29 3e [2] 35 11 }

  condition:
    any of them
}