rule TTP_XOR_QUAD_CurrentVersionRun_9fe7 {
  strings:
    $key_9fe7 = { cc 88 [2] e8 86 [2] c3 aa [2] ed 88 [2] f9 93 [2] f6 89 [2] e8 94 [2] ea 95 [2] f1 93 [2] ed 94 [2] f1 bb }

  condition:
    any of them
}