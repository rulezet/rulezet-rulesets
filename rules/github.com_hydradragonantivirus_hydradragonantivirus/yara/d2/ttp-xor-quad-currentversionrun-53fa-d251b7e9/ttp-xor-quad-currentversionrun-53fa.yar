rule TTP_XOR_QUAD_CurrentVersionRun_53fa {
  strings:
    $key_53fa = { 00 95 [2] 24 9b [2] 0f b7 [2] 21 95 [2] 35 8e [2] 3a 94 [2] 24 89 [2] 26 88 [2] 3d 8e [2] 21 89 [2] 3d a6 }

  condition:
    any of them
}