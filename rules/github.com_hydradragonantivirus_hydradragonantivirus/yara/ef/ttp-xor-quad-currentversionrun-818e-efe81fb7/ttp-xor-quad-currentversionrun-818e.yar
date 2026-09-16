rule TTP_XOR_QUAD_CurrentVersionRun_818e {
  strings:
    $key_818e = { d2 e1 [2] f6 ef [2] dd c3 [2] f3 e1 [2] e7 fa [2] e8 e0 [2] f6 fd [2] f4 fc [2] ef fa [2] f3 fd [2] ef d2 }

  condition:
    any of them
}