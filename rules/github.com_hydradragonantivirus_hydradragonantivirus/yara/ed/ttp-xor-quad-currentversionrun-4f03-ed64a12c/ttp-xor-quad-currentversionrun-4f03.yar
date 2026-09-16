rule TTP_XOR_QUAD_CurrentVersionRun_4f03 {
  strings:
    $key_4f03 = { 1c 6c [2] 38 62 [2] 13 4e [2] 3d 6c [2] 29 77 [2] 26 6d [2] 38 70 [2] 3a 71 [2] 21 77 [2] 3d 70 [2] 21 5f }

  condition:
    any of them
}