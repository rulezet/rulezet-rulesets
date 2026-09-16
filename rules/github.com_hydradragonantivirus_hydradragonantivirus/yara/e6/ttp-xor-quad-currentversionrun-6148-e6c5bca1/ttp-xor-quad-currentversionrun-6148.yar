rule TTP_XOR_QUAD_CurrentVersionRun_6148 {
  strings:
    $key_6148 = { 32 27 [2] 16 29 [2] 3d 05 [2] 13 27 [2] 07 3c [2] 08 26 [2] 16 3b [2] 14 3a [2] 0f 3c [2] 13 3b [2] 0f 14 }

  condition:
    any of them
}