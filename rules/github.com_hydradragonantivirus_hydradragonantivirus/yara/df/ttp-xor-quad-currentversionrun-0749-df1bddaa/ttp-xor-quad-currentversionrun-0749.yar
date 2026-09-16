rule TTP_XOR_QUAD_CurrentVersionRun_0749 {
  strings:
    $key_0749 = { 54 26 [2] 70 28 [2] 5b 04 [2] 75 26 [2] 61 3d [2] 6e 27 [2] 70 3a [2] 72 3b [2] 69 3d [2] 75 3a [2] 69 15 }

  condition:
    any of them
}