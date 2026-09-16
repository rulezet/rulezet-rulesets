rule TTP_XOR_QUAD_CurrentVersionRun_9ab6 {
  strings:
    $key_9ab6 = { c9 d9 [2] ed d7 [2] c6 fb [2] e8 d9 [2] fc c2 [2] f3 d8 [2] ed c5 [2] ef c4 [2] f4 c2 [2] e8 c5 [2] f4 ea }

  condition:
    any of them
}