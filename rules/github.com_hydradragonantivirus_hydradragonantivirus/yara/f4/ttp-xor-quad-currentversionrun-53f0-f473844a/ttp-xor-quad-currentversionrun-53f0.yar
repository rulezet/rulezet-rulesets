rule TTP_XOR_QUAD_CurrentVersionRun_53f0 {
  strings:
    $key_53f0 = { 00 9f [2] 24 91 [2] 0f bd [2] 21 9f [2] 35 84 [2] 3a 9e [2] 24 83 [2] 26 82 [2] 3d 84 [2] 21 83 [2] 3d ac }

  condition:
    any of them
}