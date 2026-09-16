rule TTP_XOR_QUAD_CurrentVersionRun_3e52 {
  strings:
    $key_3e52 = { 6d 3d [2] 49 33 [2] 62 1f [2] 4c 3d [2] 58 26 [2] 57 3c [2] 49 21 [2] 4b 20 [2] 50 26 [2] 4c 21 [2] 50 0e }

  condition:
    any of them
}