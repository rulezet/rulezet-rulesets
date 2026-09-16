rule TTP_XOR_QUAD_CurrentVersionRun_5b24 {
  strings:
    $key_5b24 = { 08 4b [2] 2c 45 [2] 07 69 [2] 29 4b [2] 3d 50 [2] 32 4a [2] 2c 57 [2] 2e 56 [2] 35 50 [2] 29 57 [2] 35 78 }

  condition:
    any of them
}