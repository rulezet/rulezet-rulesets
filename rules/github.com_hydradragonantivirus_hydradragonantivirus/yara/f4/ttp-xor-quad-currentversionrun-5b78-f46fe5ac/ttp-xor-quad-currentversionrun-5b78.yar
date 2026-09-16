rule TTP_XOR_QUAD_CurrentVersionRun_5b78 {
  strings:
    $key_5b78 = { 08 17 [2] 2c 19 [2] 07 35 [2] 29 17 [2] 3d 0c [2] 32 16 [2] 2c 0b [2] 2e 0a [2] 35 0c [2] 29 0b [2] 35 24 }

  condition:
    any of them
}