rule TTP_XOR_QUAD_CurrentVersionRun_84ce {
  strings:
    $key_84ce = { d7 a1 [2] f3 af [2] d8 83 [2] f6 a1 [2] e2 ba [2] ed a0 [2] f3 bd [2] f1 bc [2] ea ba [2] f6 bd [2] ea 92 }

  condition:
    any of them
}