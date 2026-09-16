rule TTP_XOR_QUAD_CurrentVersionRun_e123 {
  strings:
    $key_e123 = { b2 4c [2] 96 42 [2] bd 6e [2] 93 4c [2] 87 57 [2] 88 4d [2] 96 50 [2] 94 51 [2] 8f 57 [2] 93 50 [2] 8f 7f }

  condition:
    any of them
}