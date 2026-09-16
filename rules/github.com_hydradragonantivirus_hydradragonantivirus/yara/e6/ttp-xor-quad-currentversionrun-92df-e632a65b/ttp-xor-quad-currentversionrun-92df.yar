rule TTP_XOR_QUAD_CurrentVersionRun_92df {
  strings:
    $key_92df = { c1 b0 [2] e5 be [2] ce 92 [2] e0 b0 [2] f4 ab [2] fb b1 [2] e5 ac [2] e7 ad [2] fc ab [2] e0 ac [2] fc 83 }

  condition:
    any of them
}