rule TTP_XOR_QUAD_CurrentVersionRun_5448 {
  strings:
    $key_5448 = { 07 27 [2] 23 29 [2] 08 05 [2] 26 27 [2] 32 3c [2] 3d 26 [2] 23 3b [2] 21 3a [2] 3a 3c [2] 26 3b [2] 3a 14 }

  condition:
    any of them
}