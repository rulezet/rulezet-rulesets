rule TTP_XOR_QUAD_CurrentVersionRun_542b {
  strings:
    $key_542b = { 07 44 [2] 23 4a [2] 08 66 [2] 26 44 [2] 32 5f [2] 3d 45 [2] 23 58 [2] 21 59 [2] 3a 5f [2] 26 58 [2] 3a 77 }

  condition:
    any of them
}