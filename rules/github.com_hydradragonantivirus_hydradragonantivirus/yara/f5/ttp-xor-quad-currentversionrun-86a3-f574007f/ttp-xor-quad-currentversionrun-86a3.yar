rule TTP_XOR_QUAD_CurrentVersionRun_86a3 {
  strings:
    $key_86a3 = { d5 cc [2] f1 c2 [2] da ee [2] f4 cc [2] e0 d7 [2] ef cd [2] f1 d0 [2] f3 d1 [2] e8 d7 [2] f4 d0 [2] e8 ff }

  condition:
    any of them
}