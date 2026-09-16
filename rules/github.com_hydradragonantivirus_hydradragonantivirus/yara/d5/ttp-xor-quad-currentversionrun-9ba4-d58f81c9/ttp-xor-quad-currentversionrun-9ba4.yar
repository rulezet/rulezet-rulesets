rule TTP_XOR_QUAD_CurrentVersionRun_9ba4 {
  strings:
    $key_9ba4 = { c8 cb [2] ec c5 [2] c7 e9 [2] e9 cb [2] fd d0 [2] f2 ca [2] ec d7 [2] ee d6 [2] f5 d0 [2] e9 d7 [2] f5 f8 }

  condition:
    any of them
}