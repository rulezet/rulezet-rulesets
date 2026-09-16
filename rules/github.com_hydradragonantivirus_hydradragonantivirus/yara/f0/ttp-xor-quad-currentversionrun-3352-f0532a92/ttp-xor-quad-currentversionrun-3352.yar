rule TTP_XOR_QUAD_CurrentVersionRun_3352 {
  strings:
    $key_3352 = { 60 3d [2] 44 33 [2] 6f 1f [2] 41 3d [2] 55 26 [2] 5a 3c [2] 44 21 [2] 46 20 [2] 5d 26 [2] 41 21 [2] 5d 0e }

  condition:
    any of them
}