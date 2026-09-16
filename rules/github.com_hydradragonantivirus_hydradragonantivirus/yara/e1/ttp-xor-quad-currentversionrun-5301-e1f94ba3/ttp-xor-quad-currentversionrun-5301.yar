rule TTP_XOR_QUAD_CurrentVersionRun_5301 {
  strings:
    $key_5301 = { 00 6e [2] 24 60 [2] 0f 4c [2] 21 6e [2] 35 75 [2] 3a 6f [2] 24 72 [2] 26 73 [2] 3d 75 [2] 21 72 [2] 3d 5d }

  condition:
    any of them
}