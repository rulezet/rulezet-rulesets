rule TTP_XOR_QUAD_CurrentVersionRun_6104 {
  strings:
    $key_6104 = { 32 6b [2] 16 65 [2] 3d 49 [2] 13 6b [2] 07 70 [2] 08 6a [2] 16 77 [2] 14 76 [2] 0f 70 [2] 13 77 [2] 0f 58 }

  condition:
    any of them
}