rule TTP_XOR_QUAD_CurrentVersionRun_8e81 {
  strings:
    $key_8e81 = { dd ee [2] f9 e0 [2] d2 cc [2] fc ee [2] e8 f5 [2] e7 ef [2] f9 f2 [2] fb f3 [2] e0 f5 [2] fc f2 [2] e0 dd }

  condition:
    any of them
}