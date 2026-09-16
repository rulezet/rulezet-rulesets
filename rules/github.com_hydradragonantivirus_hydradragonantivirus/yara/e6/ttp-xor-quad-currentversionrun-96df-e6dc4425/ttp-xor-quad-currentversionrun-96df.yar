rule TTP_XOR_QUAD_CurrentVersionRun_96df {
  strings:
    $key_96df = { c5 b0 [2] e1 be [2] ca 92 [2] e4 b0 [2] f0 ab [2] ff b1 [2] e1 ac [2] e3 ad [2] f8 ab [2] e4 ac [2] f8 83 }

  condition:
    any of them
}