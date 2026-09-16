rule TTP_XOR_QUAD_CurrentVersionRun_9fb2 {
  strings:
    $key_9fb2 = { cc dd [2] e8 d3 [2] c3 ff [2] ed dd [2] f9 c6 [2] f6 dc [2] e8 c1 [2] ea c0 [2] f1 c6 [2] ed c1 [2] f1 ee }

  condition:
    any of them
}