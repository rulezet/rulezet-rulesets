rule TTP_XOR_QUAD_CurrentVersionRun_80f6 {
  strings:
    $key_80f6 = { d3 99 [2] f7 97 [2] dc bb [2] f2 99 [2] e6 82 [2] e9 98 [2] f7 85 [2] f5 84 [2] ee 82 [2] f2 85 [2] ee aa }

  condition:
    any of them
}