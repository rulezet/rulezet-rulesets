rule TTP_XOR_QUAD_CurrentVersionRun_5b7d {
  strings:
    $key_5b7d = { 08 12 [2] 2c 1c [2] 07 30 [2] 29 12 [2] 3d 09 [2] 32 13 [2] 2c 0e [2] 2e 0f [2] 35 09 [2] 29 0e [2] 35 21 }

  condition:
    any of them
}