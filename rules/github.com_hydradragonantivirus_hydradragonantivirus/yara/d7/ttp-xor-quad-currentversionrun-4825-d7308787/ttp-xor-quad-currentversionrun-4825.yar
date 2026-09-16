rule TTP_XOR_QUAD_CurrentVersionRun_4825 {
  strings:
    $key_4825 = { 1b 4a [2] 3f 44 [2] 14 68 [2] 3a 4a [2] 2e 51 [2] 21 4b [2] 3f 56 [2] 3d 57 [2] 26 51 [2] 3a 56 [2] 26 79 }

  condition:
    any of them
}