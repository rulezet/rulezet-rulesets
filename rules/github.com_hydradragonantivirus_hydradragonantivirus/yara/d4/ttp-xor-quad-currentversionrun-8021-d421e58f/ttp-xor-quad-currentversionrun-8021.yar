rule TTP_XOR_QUAD_CurrentVersionRun_8021 {
  strings:
    $key_8021 = { d3 4e [2] f7 40 [2] dc 6c [2] f2 4e [2] e6 55 [2] e9 4f [2] f7 52 [2] f5 53 [2] ee 55 [2] f2 52 [2] ee 7d }

  condition:
    any of them
}