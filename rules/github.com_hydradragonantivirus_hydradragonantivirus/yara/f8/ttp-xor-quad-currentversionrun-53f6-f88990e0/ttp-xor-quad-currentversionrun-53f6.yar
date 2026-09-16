rule TTP_XOR_QUAD_CurrentVersionRun_53f6 {
  strings:
    $key_53f6 = { 00 99 [2] 24 97 [2] 0f bb [2] 21 99 [2] 35 82 [2] 3a 98 [2] 24 85 [2] 26 84 [2] 3d 82 [2] 21 85 [2] 3d aa }

  condition:
    any of them
}