rule TTP_XOR_QUAD_CurrentVersionRun_5b35 {
  strings:
    $key_5b35 = { 08 5a [2] 2c 54 [2] 07 78 [2] 29 5a [2] 3d 41 [2] 32 5b [2] 2c 46 [2] 2e 47 [2] 35 41 [2] 29 46 [2] 35 69 }

  condition:
    any of them
}