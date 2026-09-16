rule TTP_XOR_QUAD_CurrentVersionRun_f849 {
  strings:
    $key_f849 = { ab 26 [2] 8f 28 [2] a4 04 [2] 8a 26 [2] 9e 3d [2] 91 27 [2] 8f 3a [2] 8d 3b [2] 96 3d [2] 8a 3a [2] 96 15 }

  condition:
    any of them
}