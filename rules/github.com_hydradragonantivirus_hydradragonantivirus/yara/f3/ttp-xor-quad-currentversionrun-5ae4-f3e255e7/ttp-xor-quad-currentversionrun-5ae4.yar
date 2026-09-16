rule TTP_XOR_QUAD_CurrentVersionRun_5ae4 {
  strings:
    $key_5ae4 = { 09 8b [2] 2d 85 [2] 06 a9 [2] 28 8b [2] 3c 90 [2] 33 8a [2] 2d 97 [2] 2f 96 [2] 34 90 [2] 28 97 [2] 34 b8 }

  condition:
    any of them
}