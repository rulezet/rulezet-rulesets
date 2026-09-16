rule TTP_XOR_QUAD_CurrentVersionRun_9f87 {
  strings:
    $key_9f87 = { cc e8 [2] e8 e6 [2] c3 ca [2] ed e8 [2] f9 f3 [2] f6 e9 [2] e8 f4 [2] ea f5 [2] f1 f3 [2] ed f4 [2] f1 db }

  condition:
    any of them
}