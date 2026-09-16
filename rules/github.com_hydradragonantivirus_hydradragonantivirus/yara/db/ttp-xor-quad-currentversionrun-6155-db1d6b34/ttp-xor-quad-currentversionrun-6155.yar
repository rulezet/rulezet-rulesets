rule TTP_XOR_QUAD_CurrentVersionRun_6155 {
  strings:
    $key_6155 = { 32 3a [2] 16 34 [2] 3d 18 [2] 13 3a [2] 07 21 [2] 08 3b [2] 16 26 [2] 14 27 [2] 0f 21 [2] 13 26 [2] 0f 09 }

  condition:
    any of them
}