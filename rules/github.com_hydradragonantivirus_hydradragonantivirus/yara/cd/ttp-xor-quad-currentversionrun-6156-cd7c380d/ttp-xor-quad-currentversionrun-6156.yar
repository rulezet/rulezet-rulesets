rule TTP_XOR_QUAD_CurrentVersionRun_6156 {
  strings:
    $key_6156 = { 32 39 [2] 16 37 [2] 3d 1b [2] 13 39 [2] 07 22 [2] 08 38 [2] 16 25 [2] 14 24 [2] 0f 22 [2] 13 25 [2] 0f 0a }

  condition:
    any of them
}