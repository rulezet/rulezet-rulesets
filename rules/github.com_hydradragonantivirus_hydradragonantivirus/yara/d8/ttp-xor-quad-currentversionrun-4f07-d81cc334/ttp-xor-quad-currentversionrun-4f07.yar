rule TTP_XOR_QUAD_CurrentVersionRun_4f07 {
  strings:
    $key_4f07 = { 1c 68 [2] 38 66 [2] 13 4a [2] 3d 68 [2] 29 73 [2] 26 69 [2] 38 74 [2] 3a 75 [2] 21 73 [2] 3d 74 [2] 21 5b }

  condition:
    any of them
}