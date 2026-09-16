rule TTP_XOR_QUAD_CurrentVersionRun_4836 {
  strings:
    $key_4836 = { 1b 59 [2] 3f 57 [2] 14 7b [2] 3a 59 [2] 2e 42 [2] 21 58 [2] 3f 45 [2] 3d 44 [2] 26 42 [2] 3a 45 [2] 26 6a }

  condition:
    any of them
}