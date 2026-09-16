rule TTP_XOR_QUAD_CurrentVersionRun_1149 {
  strings:
    $key_1149 = { 42 26 [2] 66 28 [2] 4d 04 [2] 63 26 [2] 77 3d [2] 78 27 [2] 66 3a [2] 64 3b [2] 7f 3d [2] 63 3a [2] 7f 15 }

  condition:
    any of them
}