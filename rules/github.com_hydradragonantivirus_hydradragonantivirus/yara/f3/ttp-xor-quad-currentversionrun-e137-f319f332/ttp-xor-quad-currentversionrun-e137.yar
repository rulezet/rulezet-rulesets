rule TTP_XOR_QUAD_CurrentVersionRun_e137 {
  strings:
    $key_e137 = { b2 58 [2] 96 56 [2] bd 7a [2] 93 58 [2] 87 43 [2] 88 59 [2] 96 44 [2] 94 45 [2] 8f 43 [2] 93 44 [2] 8f 6b }

  condition:
    any of them
}