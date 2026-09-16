rule TTP_XOR_QUAD_CurrentVersionRun_e143 {
  strings:
    $key_e143 = { b2 2c [2] 96 22 [2] bd 0e [2] 93 2c [2] 87 37 [2] 88 2d [2] 96 30 [2] 94 31 [2] 8f 37 [2] 93 30 [2] 8f 1f }

  condition:
    any of them
}