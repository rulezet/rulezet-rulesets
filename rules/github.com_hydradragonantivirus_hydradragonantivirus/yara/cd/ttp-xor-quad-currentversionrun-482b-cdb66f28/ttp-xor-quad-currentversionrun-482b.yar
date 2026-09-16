rule TTP_XOR_QUAD_CurrentVersionRun_482b {
  strings:
    $key_482b = { 1b 44 [2] 3f 4a [2] 14 66 [2] 3a 44 [2] 2e 5f [2] 21 45 [2] 3f 58 [2] 3d 59 [2] 26 5f [2] 3a 58 [2] 26 77 }

  condition:
    any of them
}