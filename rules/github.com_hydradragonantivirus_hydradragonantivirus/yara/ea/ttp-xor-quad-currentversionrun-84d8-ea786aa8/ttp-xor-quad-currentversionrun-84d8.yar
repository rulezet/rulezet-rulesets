rule TTP_XOR_QUAD_CurrentVersionRun_84d8 {
  strings:
    $key_84d8 = { d7 b7 [2] f3 b9 [2] d8 95 [2] f6 b7 [2] e2 ac [2] ed b6 [2] f3 ab [2] f1 aa [2] ea ac [2] f6 ab [2] ea 84 }

  condition:
    any of them
}