rule TTP_XOR_QUAD_CurrentVersionRun_9fa3 {
  strings:
    $key_9fa3 = { cc cc [2] e8 c2 [2] c3 ee [2] ed cc [2] f9 d7 [2] f6 cd [2] e8 d0 [2] ea d1 [2] f1 d7 [2] ed d0 [2] f1 ff }

  condition:
    any of them
}