rule TTP_XOR_QUAD_CurrentVersionRun_4874 {
  strings:
    $key_4874 = { 1b 1b [2] 3f 15 [2] 14 39 [2] 3a 1b [2] 2e 00 [2] 21 1a [2] 3f 07 [2] 3d 06 [2] 26 00 [2] 3a 07 [2] 26 28 }

  condition:
    any of them
}