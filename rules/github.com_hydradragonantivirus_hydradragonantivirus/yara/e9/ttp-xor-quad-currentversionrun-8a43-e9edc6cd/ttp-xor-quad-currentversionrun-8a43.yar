rule TTP_XOR_QUAD_CurrentVersionRun_8a43 {
  strings:
    $key_8a43 = { d9 2c [2] fd 22 [2] d6 0e [2] f8 2c [2] ec 37 [2] e3 2d [2] fd 30 [2] ff 31 [2] e4 37 [2] f8 30 [2] e4 1f }

  condition:
    any of them
}