rule TTP_XOR_QUAD_CurrentVersionRun_4805 {
  strings:
    $key_4805 = { 1b 6a [2] 3f 64 [2] 14 48 [2] 3a 6a [2] 2e 71 [2] 21 6b [2] 3f 76 [2] 3d 77 [2] 26 71 [2] 3a 76 [2] 26 59 }

  condition:
    any of them
}