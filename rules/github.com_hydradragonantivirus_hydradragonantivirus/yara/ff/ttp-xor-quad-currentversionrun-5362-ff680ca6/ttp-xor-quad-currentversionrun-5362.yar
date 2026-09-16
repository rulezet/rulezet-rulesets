rule TTP_XOR_QUAD_CurrentVersionRun_5362 {
  strings:
    $key_5362 = { 00 0d [2] 24 03 [2] 0f 2f [2] 21 0d [2] 35 16 [2] 3a 0c [2] 24 11 [2] 26 10 [2] 3d 16 [2] 21 11 [2] 3d 3e }

  condition:
    any of them
}