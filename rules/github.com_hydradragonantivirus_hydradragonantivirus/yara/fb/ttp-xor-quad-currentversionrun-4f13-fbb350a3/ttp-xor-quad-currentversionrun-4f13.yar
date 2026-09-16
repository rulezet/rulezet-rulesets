rule TTP_XOR_QUAD_CurrentVersionRun_4f13 {
  strings:
    $key_4f13 = { 1c 7c [2] 38 72 [2] 13 5e [2] 3d 7c [2] 29 67 [2] 26 7d [2] 38 60 [2] 3a 61 [2] 21 67 [2] 3d 60 [2] 21 4f }

  condition:
    any of them
}