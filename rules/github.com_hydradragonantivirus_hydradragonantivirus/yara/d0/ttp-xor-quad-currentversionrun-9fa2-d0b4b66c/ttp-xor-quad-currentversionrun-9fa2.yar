rule TTP_XOR_QUAD_CurrentVersionRun_9fa2 {
  strings:
    $key_9fa2 = { cc cd [2] e8 c3 [2] c3 ef [2] ed cd [2] f9 d6 [2] f6 cc [2] e8 d1 [2] ea d0 [2] f1 d6 [2] ed d1 [2] f1 fe }

  condition:
    any of them
}