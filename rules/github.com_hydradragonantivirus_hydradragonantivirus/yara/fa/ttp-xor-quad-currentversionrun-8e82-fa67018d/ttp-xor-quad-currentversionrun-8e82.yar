rule TTP_XOR_QUAD_CurrentVersionRun_8e82 {
  strings:
    $key_8e82 = { dd ed [2] f9 e3 [2] d2 cf [2] fc ed [2] e8 f6 [2] e7 ec [2] f9 f1 [2] fb f0 [2] e0 f6 [2] fc f1 [2] e0 de }

  condition:
    any of them
}