rule TTP_XOR_QUAD_CurrentVersionRun_5b04 {
  strings:
    $key_5b04 = { 08 6b [2] 2c 65 [2] 07 49 [2] 29 6b [2] 3d 70 [2] 32 6a [2] 2c 77 [2] 2e 76 [2] 35 70 [2] 29 77 [2] 35 58 }

  condition:
    any of them
}