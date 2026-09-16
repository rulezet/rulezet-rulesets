rule TTP_XOR_QUAD_CurrentVersionRun_8ccc {
  strings:
    $key_8ccc = { df a3 [2] fb ad [2] d0 81 [2] fe a3 [2] ea b8 [2] e5 a2 [2] fb bf [2] f9 be [2] e2 b8 [2] fe bf [2] e2 90 }

  condition:
    any of them
}