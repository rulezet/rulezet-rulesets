rule TTP_XOR_QUAD_CurrentVersionRun_4f76 {
  strings:
    $key_4f76 = { 1c 19 [2] 38 17 [2] 13 3b [2] 3d 19 [2] 29 02 [2] 26 18 [2] 38 05 [2] 3a 04 [2] 21 02 [2] 3d 05 [2] 21 2a }

  condition:
    any of them
}