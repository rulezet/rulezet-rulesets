rule TTP_XOR_QUAD_CurrentVersionRun_9ed0 {
  strings:
    $key_9ed0 = { cd bf [2] e9 b1 [2] c2 9d [2] ec bf [2] f8 a4 [2] f7 be [2] e9 a3 [2] eb a2 [2] f0 a4 [2] ec a3 [2] f0 8c }

  condition:
    any of them
}