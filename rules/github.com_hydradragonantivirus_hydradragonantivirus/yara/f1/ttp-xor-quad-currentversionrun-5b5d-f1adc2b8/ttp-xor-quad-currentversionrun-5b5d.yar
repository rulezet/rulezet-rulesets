rule TTP_XOR_QUAD_CurrentVersionRun_5b5d {
  strings:
    $key_5b5d = { 08 32 [2] 2c 3c [2] 07 10 [2] 29 32 [2] 3d 29 [2] 32 33 [2] 2c 2e [2] 2e 2f [2] 35 29 [2] 29 2e [2] 35 01 }

  condition:
    any of them
}