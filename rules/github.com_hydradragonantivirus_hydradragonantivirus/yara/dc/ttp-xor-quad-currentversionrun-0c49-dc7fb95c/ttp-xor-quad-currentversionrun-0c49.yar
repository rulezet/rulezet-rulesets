rule TTP_XOR_QUAD_CurrentVersionRun_0c49 {
  strings:
    $key_0c49 = { 5f 26 [2] 7b 28 [2] 50 04 [2] 7e 26 [2] 6a 3d [2] 65 27 [2] 7b 3a [2] 79 3b [2] 62 3d [2] 7e 3a [2] 62 15 }

  condition:
    any of them
}