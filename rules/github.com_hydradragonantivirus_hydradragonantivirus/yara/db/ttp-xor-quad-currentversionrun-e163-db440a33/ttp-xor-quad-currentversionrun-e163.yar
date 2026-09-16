rule TTP_XOR_QUAD_CurrentVersionRun_e163 {
  strings:
    $key_e163 = { b2 0c [2] 96 02 [2] bd 2e [2] 93 0c [2] 87 17 [2] 88 0d [2] 96 10 [2] 94 11 [2] 8f 17 [2] 93 10 [2] 8f 3f }

  condition:
    any of them
}