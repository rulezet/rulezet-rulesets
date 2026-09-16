rule TTP_XOR_QUAD_CurrentVersionRun_1d52 {
  strings:
    $key_1d52 = { 4e 3d [2] 6a 33 [2] 41 1f [2] 6f 3d [2] 7b 26 [2] 74 3c [2] 6a 21 [2] 68 20 [2] 73 26 [2] 6f 21 [2] 73 0e }

  condition:
    any of them
}