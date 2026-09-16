rule TTP_XOR_QUAD_CurrentVersionRun_e1c8 {
  strings:
    $key_e1c8 = { b2 a7 [2] 96 a9 [2] bd 85 [2] 93 a7 [2] 87 bc [2] 88 a6 [2] 96 bb [2] 94 ba [2] 8f bc [2] 93 bb [2] 8f 94 }

  condition:
    any of them
}