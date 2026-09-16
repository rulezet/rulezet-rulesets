rule TTP_XOR_QUAD_CurrentVersionRun_4f22 {
  strings:
    $key_4f22 = { 1c 4d [2] 38 43 [2] 13 6f [2] 3d 4d [2] 29 56 [2] 26 4c [2] 38 51 [2] 3a 50 [2] 21 56 [2] 3d 51 [2] 21 7e }

  condition:
    any of them
}