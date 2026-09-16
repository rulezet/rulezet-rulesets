rule TTP_XOR_QUAD_CurrentVersionRun_53f3 {
  strings:
    $key_53f3 = { 00 9c [2] 24 92 [2] 0f be [2] 21 9c [2] 35 87 [2] 3a 9d [2] 24 80 [2] 26 81 [2] 3d 87 [2] 21 80 [2] 3d af }

  condition:
    any of them
}