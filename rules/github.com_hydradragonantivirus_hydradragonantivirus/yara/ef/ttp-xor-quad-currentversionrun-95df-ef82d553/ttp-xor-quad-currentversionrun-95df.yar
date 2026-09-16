rule TTP_XOR_QUAD_CurrentVersionRun_95df {
  strings:
    $key_95df = { c6 b0 [2] e2 be [2] c9 92 [2] e7 b0 [2] f3 ab [2] fc b1 [2] e2 ac [2] e0 ad [2] fb ab [2] e7 ac [2] fb 83 }

  condition:
    any of them
}