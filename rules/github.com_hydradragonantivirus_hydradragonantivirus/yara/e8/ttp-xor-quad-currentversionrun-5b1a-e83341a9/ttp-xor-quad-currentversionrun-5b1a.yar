rule TTP_XOR_QUAD_CurrentVersionRun_5b1a {
  strings:
    $key_5b1a = { 08 75 [2] 2c 7b [2] 07 57 [2] 29 75 [2] 3d 6e [2] 32 74 [2] 2c 69 [2] 2e 68 [2] 35 6e [2] 29 69 [2] 35 46 }

  condition:
    any of them
}