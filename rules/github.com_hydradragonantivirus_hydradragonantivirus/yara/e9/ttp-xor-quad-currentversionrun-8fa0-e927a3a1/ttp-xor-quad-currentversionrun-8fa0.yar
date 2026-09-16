rule TTP_XOR_QUAD_CurrentVersionRun_8fa0 {
  strings:
    $key_8fa0 = { dc cf [2] f8 c1 [2] d3 ed [2] fd cf [2] e9 d4 [2] e6 ce [2] f8 d3 [2] fa d2 [2] e1 d4 [2] fd d3 [2] e1 fc }

  condition:
    any of them
}