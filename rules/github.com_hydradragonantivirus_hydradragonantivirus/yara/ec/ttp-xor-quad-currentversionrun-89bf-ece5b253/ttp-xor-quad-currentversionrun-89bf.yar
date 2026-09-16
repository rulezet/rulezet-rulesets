rule TTP_XOR_QUAD_CurrentVersionRun_89bf {
  strings:
    $key_89bf = { da d0 [2] fe de [2] d5 f2 [2] fb d0 [2] ef cb [2] e0 d1 [2] fe cc [2] fc cd [2] e7 cb [2] fb cc [2] e7 e3 }

  condition:
    any of them
}