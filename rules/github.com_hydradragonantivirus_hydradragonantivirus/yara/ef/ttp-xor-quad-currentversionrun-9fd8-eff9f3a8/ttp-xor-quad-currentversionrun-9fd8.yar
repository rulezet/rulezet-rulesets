rule TTP_XOR_QUAD_CurrentVersionRun_9fd8 {
  strings:
    $key_9fd8 = { cc b7 [2] e8 b9 [2] c3 95 [2] ed b7 [2] f9 ac [2] f6 b6 [2] e8 ab [2] ea aa [2] f1 ac [2] ed ab [2] f1 84 }

  condition:
    any of them
}