rule TTP_XOR_QUAD_CurrentVersionRun_80c9 {
  strings:
    $key_80c9 = { d3 a6 [2] f7 a8 [2] dc 84 [2] f2 a6 [2] e6 bd [2] e9 a7 [2] f7 ba [2] f5 bb [2] ee bd [2] f2 ba [2] ee 95 }

  condition:
    any of them
}