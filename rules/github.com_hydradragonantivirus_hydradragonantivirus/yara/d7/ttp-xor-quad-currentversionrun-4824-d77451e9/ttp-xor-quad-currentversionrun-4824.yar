rule TTP_XOR_QUAD_CurrentVersionRun_4824 {
  strings:
    $key_4824 = { 1b 4b [2] 3f 45 [2] 14 69 [2] 3a 4b [2] 2e 50 [2] 21 4a [2] 3f 57 [2] 3d 56 [2] 26 50 [2] 3a 57 [2] 26 78 }

  condition:
    any of them
}