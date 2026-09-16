rule TTP_XOR_QUAD_CurrentVersionRun_1f52 {
  strings:
    $key_1f52 = { 4c 3d [2] 68 33 [2] 43 1f [2] 6d 3d [2] 79 26 [2] 76 3c [2] 68 21 [2] 6a 20 [2] 71 26 [2] 6d 21 [2] 71 0e }

  condition:
    any of them
}