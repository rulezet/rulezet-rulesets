rule TTP_XOR_QUAD_CurrentVersionRun_4835 {
  strings:
    $key_4835 = { 1b 5a [2] 3f 54 [2] 14 78 [2] 3a 5a [2] 2e 41 [2] 21 5b [2] 3f 46 [2] 3d 47 [2] 26 41 [2] 3a 46 [2] 26 69 }

  condition:
    any of them
}