rule TTP_XOR_QUAD_CurrentVersionRun_89c9 {
  strings:
    $key_89c9 = { da a6 [2] fe a8 [2] d5 84 [2] fb a6 [2] ef bd [2] e0 a7 [2] fe ba [2] fc bb [2] e7 bd [2] fb ba [2] e7 95 }

  condition:
    any of them
}