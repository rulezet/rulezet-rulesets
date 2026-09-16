rule TTP_XOR_QUAD_CurrentVersionRun_4f36 {
  strings:
    $key_4f36 = { 1c 59 [2] 38 57 [2] 13 7b [2] 3d 59 [2] 29 42 [2] 26 58 [2] 38 45 [2] 3a 44 [2] 21 42 [2] 3d 45 [2] 21 6a }

  condition:
    any of them
}