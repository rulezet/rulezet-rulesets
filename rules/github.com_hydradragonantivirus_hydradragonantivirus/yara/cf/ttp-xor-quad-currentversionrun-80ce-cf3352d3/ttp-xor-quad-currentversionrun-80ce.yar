rule TTP_XOR_QUAD_CurrentVersionRun_80ce {
  strings:
    $key_80ce = { d3 a1 [2] f7 af [2] dc 83 [2] f2 a1 [2] e6 ba [2] e9 a0 [2] f7 bd [2] f5 bc [2] ee ba [2] f2 bd [2] ee 92 }

  condition:
    any of them
}