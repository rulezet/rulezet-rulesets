rule TTP_XOR_QUAD_CurrentVersionRun_9fc2 {
  strings:
    $key_9fc2 = { cc ad [2] e8 a3 [2] c3 8f [2] ed ad [2] f9 b6 [2] f6 ac [2] e8 b1 [2] ea b0 [2] f1 b6 [2] ed b1 [2] f1 9e }

  condition:
    any of them
}