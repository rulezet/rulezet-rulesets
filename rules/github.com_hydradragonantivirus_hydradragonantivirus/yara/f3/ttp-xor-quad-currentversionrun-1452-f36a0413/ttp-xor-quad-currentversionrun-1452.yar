rule TTP_XOR_QUAD_CurrentVersionRun_1452 {
  strings:
    $key_1452 = { 47 3d [2] 63 33 [2] 48 1f [2] 66 3d [2] 72 26 [2] 7d 3c [2] 63 21 [2] 61 20 [2] 7a 26 [2] 66 21 [2] 7a 0e }

  condition:
    any of them
}