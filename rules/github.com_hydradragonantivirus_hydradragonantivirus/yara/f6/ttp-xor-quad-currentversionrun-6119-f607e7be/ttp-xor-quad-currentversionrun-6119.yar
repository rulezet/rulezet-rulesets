rule TTP_XOR_QUAD_CurrentVersionRun_6119 {
  strings:
    $key_6119 = { 32 76 [2] 16 78 [2] 3d 54 [2] 13 76 [2] 07 6d [2] 08 77 [2] 16 6a [2] 14 6b [2] 0f 6d [2] 13 6a [2] 0f 45 }

  condition:
    any of them
}