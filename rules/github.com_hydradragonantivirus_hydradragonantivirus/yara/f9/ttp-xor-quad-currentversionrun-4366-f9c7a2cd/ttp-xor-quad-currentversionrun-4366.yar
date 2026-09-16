rule TTP_XOR_QUAD_CurrentVersionRun_4366 {
  strings:
    $key_4366 = { 10 09 [2] 34 07 [2] 1f 2b [2] 31 09 [2] 25 12 [2] 2a 08 [2] 34 15 [2] 36 14 [2] 2d 12 [2] 31 15 [2] 2d 3a }

  condition:
    any of them
}