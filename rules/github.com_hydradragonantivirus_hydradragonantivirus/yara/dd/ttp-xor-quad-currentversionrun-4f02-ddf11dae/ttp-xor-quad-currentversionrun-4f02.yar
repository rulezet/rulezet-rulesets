rule TTP_XOR_QUAD_CurrentVersionRun_4f02 {
  strings:
    $key_4f02 = { 1c 6d [2] 38 63 [2] 13 4f [2] 3d 6d [2] 29 76 [2] 26 6c [2] 38 71 [2] 3a 70 [2] 21 76 [2] 3d 71 [2] 21 5e }

  condition:
    any of them
}