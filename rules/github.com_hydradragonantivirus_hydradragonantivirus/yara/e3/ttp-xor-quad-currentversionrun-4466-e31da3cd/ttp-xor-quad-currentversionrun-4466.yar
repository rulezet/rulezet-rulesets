rule TTP_XOR_QUAD_CurrentVersionRun_4466 {
  strings:
    $key_4466 = { 17 09 [2] 33 07 [2] 18 2b [2] 36 09 [2] 22 12 [2] 2d 08 [2] 33 15 [2] 31 14 [2] 2a 12 [2] 36 15 [2] 2a 3a }

  condition:
    any of them
}