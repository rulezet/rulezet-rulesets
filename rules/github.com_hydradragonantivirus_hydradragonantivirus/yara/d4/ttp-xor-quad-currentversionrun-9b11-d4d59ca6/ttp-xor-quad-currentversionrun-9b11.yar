rule TTP_XOR_QUAD_CurrentVersionRun_9b11 {
  strings:
    $key_9b11 = { c8 7e [2] ec 70 [2] c7 5c [2] e9 7e [2] fd 65 [2] f2 7f [2] ec 62 [2] ee 63 [2] f5 65 [2] e9 62 [2] f5 4d }

  condition:
    any of them
}