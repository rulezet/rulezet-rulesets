rule TTP_XOR_QUAD_CurrentVersionRun_4854 {
  strings:
    $key_4854 = { 1b 3b [2] 3f 35 [2] 14 19 [2] 3a 3b [2] 2e 20 [2] 21 3a [2] 3f 27 [2] 3d 26 [2] 26 20 [2] 3a 27 [2] 26 08 }

  condition:
    any of them
}