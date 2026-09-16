rule TTP_XOR_QUAD_CurrentVersionRun_6e46 {
  strings:
    $key_6e46 = { 3d 29 [2] 19 27 [2] 32 0b [2] 1c 29 [2] 08 32 [2] 07 28 [2] 19 35 [2] 1b 34 [2] 00 32 [2] 1c 35 [2] 00 1a }

  condition:
    any of them
}