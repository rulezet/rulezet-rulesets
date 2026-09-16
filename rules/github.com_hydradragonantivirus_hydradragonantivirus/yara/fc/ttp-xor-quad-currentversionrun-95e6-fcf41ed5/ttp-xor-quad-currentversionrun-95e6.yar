rule TTP_XOR_QUAD_CurrentVersionRun_95e6 {
  strings:
    $key_95e6 = { c6 89 [2] e2 87 [2] c9 ab [2] e7 89 [2] f3 92 [2] fc 88 [2] e2 95 [2] e0 94 [2] fb 92 [2] e7 95 [2] fb ba }

  condition:
    any of them
}