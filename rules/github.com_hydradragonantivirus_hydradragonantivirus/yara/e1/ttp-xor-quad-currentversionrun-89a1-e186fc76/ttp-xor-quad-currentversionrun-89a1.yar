rule TTP_XOR_QUAD_CurrentVersionRun_89a1 {
  strings:
    $key_89a1 = { da ce [2] fe c0 [2] d5 ec [2] fb ce [2] ef d5 [2] e0 cf [2] fe d2 [2] fc d3 [2] e7 d5 [2] fb d2 [2] e7 fd }

  condition:
    any of them
}