rule TTP_XOR_QUAD_CurrentVersionRun_e136 {
  strings:
    $key_e136 = { b2 59 [2] 96 57 [2] bd 7b [2] 93 59 [2] 87 42 [2] 88 58 [2] 96 45 [2] 94 44 [2] 8f 42 [2] 93 45 [2] 8f 6a }

  condition:
    any of them
}