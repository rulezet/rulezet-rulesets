rule TTP_XOR_QUAD_CurrentVersionRun_82d3 {
  strings:
    $key_82d3 = { d1 bc [2] f5 b2 [2] de 9e [2] f0 bc [2] e4 a7 [2] eb bd [2] f5 a0 [2] f7 a1 [2] ec a7 [2] f0 a0 [2] ec 8f }

  condition:
    any of them
}