rule TTP_XOR_QUAD_CurrentVersionRun_8bbb {
  strings:
    $key_8bbb = { d8 d4 [2] fc da [2] d7 f6 [2] f9 d4 [2] ed cf [2] e2 d5 [2] fc c8 [2] fe c9 [2] e5 cf [2] f9 c8 [2] e5 e7 }

  condition:
    any of them
}