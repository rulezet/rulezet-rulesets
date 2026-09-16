rule TTP_XOR_QUAD_CurrentVersionRun_5b22 {
  strings:
    $key_5b22 = { 08 4d [2] 2c 43 [2] 07 6f [2] 29 4d [2] 3d 56 [2] 32 4c [2] 2c 51 [2] 2e 50 [2] 35 56 [2] 29 51 [2] 35 7e }

  condition:
    any of them
}