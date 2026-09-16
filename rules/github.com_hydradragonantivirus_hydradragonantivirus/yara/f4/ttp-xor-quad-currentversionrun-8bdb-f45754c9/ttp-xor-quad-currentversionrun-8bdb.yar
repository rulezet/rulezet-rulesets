rule TTP_XOR_QUAD_CurrentVersionRun_8bdb {
  strings:
    $key_8bdb = { d8 b4 [2] fc ba [2] d7 96 [2] f9 b4 [2] ed af [2] e2 b5 [2] fc a8 [2] fe a9 [2] e5 af [2] f9 a8 [2] e5 87 }

  condition:
    any of them
}