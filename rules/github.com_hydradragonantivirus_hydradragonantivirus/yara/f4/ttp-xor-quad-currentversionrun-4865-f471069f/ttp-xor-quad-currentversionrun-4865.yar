rule TTP_XOR_QUAD_CurrentVersionRun_4865 {
  strings:
    $key_4865 = { 1b 0a [2] 3f 04 [2] 14 28 [2] 3a 0a [2] 2e 11 [2] 21 0b [2] 3f 16 [2] 3d 17 [2] 26 11 [2] 3a 16 [2] 26 39 }

  condition:
    any of them
}