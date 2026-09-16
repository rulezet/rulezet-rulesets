rule TTP_XOR_QUAD_CurrentVersionRun_84b2 {
  strings:
    $key_84b2 = { d7 dd [2] f3 d3 [2] d8 ff [2] f6 dd [2] e2 c6 [2] ed dc [2] f3 c1 [2] f1 c0 [2] ea c6 [2] f6 c1 [2] ea ee }

  condition:
    any of them
}