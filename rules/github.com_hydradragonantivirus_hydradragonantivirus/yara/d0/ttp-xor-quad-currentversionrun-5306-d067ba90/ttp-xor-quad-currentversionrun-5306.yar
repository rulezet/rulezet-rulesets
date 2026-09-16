rule TTP_XOR_QUAD_CurrentVersionRun_5306 {
  strings:
    $key_5306 = { 00 69 [2] 24 67 [2] 0f 4b [2] 21 69 [2] 35 72 [2] 3a 68 [2] 24 75 [2] 26 74 [2] 3d 72 [2] 21 75 [2] 3d 5a }

  condition:
    any of them
}