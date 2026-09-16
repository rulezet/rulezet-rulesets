rule TTP_XOR_QUAD_CurrentVersionRun_5476 {
  strings:
    $key_5476 = { 07 19 [2] 23 17 [2] 08 3b [2] 26 19 [2] 32 02 [2] 3d 18 [2] 23 05 [2] 21 04 [2] 3a 02 [2] 26 05 [2] 3a 2a }

  condition:
    any of them
}