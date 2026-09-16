rule TTP_XOR_QUAD_CurrentVersionRun_80e2 {
  strings:
    $key_80e2 = { d3 8d [2] f7 83 [2] dc af [2] f2 8d [2] e6 96 [2] e9 8c [2] f7 91 [2] f5 90 [2] ee 96 [2] f2 91 [2] ee be }

  condition:
    any of them
}