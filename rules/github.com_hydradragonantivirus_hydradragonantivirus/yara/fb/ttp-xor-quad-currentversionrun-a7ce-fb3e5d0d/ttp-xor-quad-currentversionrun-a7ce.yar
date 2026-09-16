rule TTP_XOR_QUAD_CurrentVersionRun_a7ce {
  strings:
    $key_a7ce = { f4 a1 [2] d0 af [2] fb 83 [2] d5 a1 [2] c1 ba [2] ce a0 [2] d0 bd [2] d2 bc [2] c9 ba [2] d5 bd [2] c9 92 }

  condition:
    any of them
}