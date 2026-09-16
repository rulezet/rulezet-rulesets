rule TTP_XOR_QUAD_CurrentVersionRun_87e1 {
  strings:
    $key_87e1 = { d4 8e [2] f0 80 [2] db ac [2] f5 8e [2] e1 95 [2] ee 8f [2] f0 92 [2] f2 93 [2] e9 95 [2] f5 92 [2] e9 bd }

  condition:
    any of them
}