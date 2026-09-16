rule TTP_XOR_QUAD_CurrentVersionRun_84b6 {
  strings:
    $key_84b6 = { d7 d9 [2] f3 d7 [2] d8 fb [2] f6 d9 [2] e2 c2 [2] ed d8 [2] f3 c5 [2] f1 c4 [2] ea c2 [2] f6 c5 [2] ea ea }

  condition:
    any of them
}