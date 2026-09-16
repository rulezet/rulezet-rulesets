rule TTP_XOR_QUAD_CurrentVersionRun_4f46 {
  strings:
    $key_4f46 = { 1c 29 [2] 38 27 [2] 13 0b [2] 3d 29 [2] 29 32 [2] 26 28 [2] 38 35 [2] 3a 34 [2] 21 32 [2] 3d 35 [2] 21 1a }

  condition:
    any of them
}