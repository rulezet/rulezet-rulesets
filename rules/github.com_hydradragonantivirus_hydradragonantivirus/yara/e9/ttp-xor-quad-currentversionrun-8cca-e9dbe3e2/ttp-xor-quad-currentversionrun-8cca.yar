rule TTP_XOR_QUAD_CurrentVersionRun_8cca {
  strings:
    $key_8cca = { df a5 [2] fb ab [2] d0 87 [2] fe a5 [2] ea be [2] e5 a4 [2] fb b9 [2] f9 b8 [2] e2 be [2] fe b9 [2] e2 96 }

  condition:
    any of them
}