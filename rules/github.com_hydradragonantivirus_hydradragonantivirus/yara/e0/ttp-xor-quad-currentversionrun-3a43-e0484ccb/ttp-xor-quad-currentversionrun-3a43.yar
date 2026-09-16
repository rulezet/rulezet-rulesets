rule TTP_XOR_QUAD_CurrentVersionRun_3a43 {
  strings:
    $key_3a43 = { 69 2c [2] 4d 22 [2] 66 0e [2] 48 2c [2] 5c 37 [2] 53 2d [2] 4d 30 [2] 4f 31 [2] 54 37 [2] 48 30 [2] 54 1f }

  condition:
    any of them
}