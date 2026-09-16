rule TTP_XOR_QUAD_CurrentVersionRun_4452 {
  strings:
    $key_4452 = { 17 3d [2] 33 33 [2] 18 1f [2] 36 3d [2] 22 26 [2] 2d 3c [2] 33 21 [2] 31 20 [2] 2a 26 [2] 36 21 [2] 2a 0e }

  condition:
    any of them
}