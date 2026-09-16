rule TTP_XOR_QUAD_CurrentVersionRun_9da2 {
  strings:
    $key_9da2 = { ce cd [2] ea c3 [2] c1 ef [2] ef cd [2] fb d6 [2] f4 cc [2] ea d1 [2] e8 d0 [2] f3 d6 [2] ef d1 [2] f3 fe }

  condition:
    any of them
}