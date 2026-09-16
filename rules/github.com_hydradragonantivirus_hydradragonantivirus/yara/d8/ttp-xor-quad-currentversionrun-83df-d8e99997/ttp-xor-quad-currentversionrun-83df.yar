rule TTP_XOR_QUAD_CurrentVersionRun_83df {
  strings:
    $key_83df = { d0 b0 [2] f4 be [2] df 92 [2] f1 b0 [2] e5 ab [2] ea b1 [2] f4 ac [2] f6 ad [2] ed ab [2] f1 ac [2] ed 83 }

  condition:
    any of them
}