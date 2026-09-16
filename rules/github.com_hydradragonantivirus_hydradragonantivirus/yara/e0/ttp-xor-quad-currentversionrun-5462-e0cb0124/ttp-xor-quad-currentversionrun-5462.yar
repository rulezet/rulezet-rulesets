rule TTP_XOR_QUAD_CurrentVersionRun_5462 {
  strings:
    $key_5462 = { 07 0d [2] 23 03 [2] 08 2f [2] 26 0d [2] 32 16 [2] 3d 0c [2] 23 11 [2] 21 10 [2] 3a 16 [2] 26 11 [2] 3a 3e }

  condition:
    any of them
}