rule TTP_XOR_QUAD_CurrentVersionRun_5b3e {
  strings:
    $key_5b3e = { 08 51 [2] 2c 5f [2] 07 73 [2] 29 51 [2] 3d 4a [2] 32 50 [2] 2c 4d [2] 2e 4c [2] 35 4a [2] 29 4d [2] 35 62 }

  condition:
    any of them
}