rule TTP_XOR_QUAD_CurrentVersionRun_8729 {
  strings:
    $key_8729 = { d4 46 [2] f0 48 [2] db 64 [2] f5 46 [2] e1 5d [2] ee 47 [2] f0 5a [2] f2 5b [2] e9 5d [2] f5 5a [2] e9 75 }

  condition:
    any of them
}