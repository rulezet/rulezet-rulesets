rule TTP_XOR_QUAD_CurrentVersionRun_8edd {
  strings:
    $key_8edd = { dd b2 [2] f9 bc [2] d2 90 [2] fc b2 [2] e8 a9 [2] e7 b3 [2] f9 ae [2] fb af [2] e0 a9 [2] fc ae [2] e0 81 }

  condition:
    any of them
}