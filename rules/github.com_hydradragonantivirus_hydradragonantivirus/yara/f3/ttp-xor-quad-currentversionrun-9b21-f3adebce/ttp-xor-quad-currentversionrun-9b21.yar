rule TTP_XOR_QUAD_CurrentVersionRun_9b21 {
  strings:
    $key_9b21 = { c8 4e [2] ec 40 [2] c7 6c [2] e9 4e [2] fd 55 [2] f2 4f [2] ec 52 [2] ee 53 [2] f5 55 [2] e9 52 [2] f5 7d }

  condition:
    any of them
}