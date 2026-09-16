rule TTP_XOR_QUAD_CurrentVersionRun_4552 {
  strings:
    $key_4552 = { 16 3d [2] 32 33 [2] 19 1f [2] 37 3d [2] 23 26 [2] 2c 3c [2] 32 21 [2] 30 20 [2] 2b 26 [2] 37 21 [2] 2b 0e }

  condition:
    any of them
}