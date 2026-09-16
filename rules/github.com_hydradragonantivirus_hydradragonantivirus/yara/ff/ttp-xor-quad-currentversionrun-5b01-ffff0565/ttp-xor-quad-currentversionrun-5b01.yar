rule TTP_XOR_QUAD_CurrentVersionRun_5b01 {
  strings:
    $key_5b01 = { 08 6e [2] 2c 60 [2] 07 4c [2] 29 6e [2] 3d 75 [2] 32 6f [2] 2c 72 [2] 2e 73 [2] 35 75 [2] 29 72 [2] 35 5d }

  condition:
    any of them
}