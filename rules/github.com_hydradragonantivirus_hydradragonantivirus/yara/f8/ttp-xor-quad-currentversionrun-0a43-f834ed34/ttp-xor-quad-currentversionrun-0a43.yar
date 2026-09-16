rule TTP_XOR_QUAD_CurrentVersionRun_0a43 {
  strings:
    $key_0a43 = { 59 2c [2] 7d 22 [2] 56 0e [2] 78 2c [2] 6c 37 [2] 63 2d [2] 7d 30 [2] 7f 31 [2] 64 37 [2] 78 30 [2] 64 1f }

  condition:
    any of them
}