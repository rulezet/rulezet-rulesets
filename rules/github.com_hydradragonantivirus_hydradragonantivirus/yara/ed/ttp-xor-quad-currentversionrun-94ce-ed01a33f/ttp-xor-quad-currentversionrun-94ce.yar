rule TTP_XOR_QUAD_CurrentVersionRun_94ce {
  strings:
    $key_94ce = { c7 a1 [2] e3 af [2] c8 83 [2] e6 a1 [2] f2 ba [2] fd a0 [2] e3 bd [2] e1 bc [2] fa ba [2] e6 bd [2] fa 92 }

  condition:
    any of them
}