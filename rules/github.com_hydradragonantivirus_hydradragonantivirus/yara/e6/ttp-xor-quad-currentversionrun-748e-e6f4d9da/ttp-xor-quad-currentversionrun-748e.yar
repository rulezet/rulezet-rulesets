rule TTP_XOR_QUAD_CurrentVersionRun_748e {
  strings:
    $key_748e = { 27 e1 [2] 03 ef [2] 28 c3 [2] 06 e1 [2] 12 fa [2] 1d e0 [2] 03 fd [2] 01 fc [2] 1a fa [2] 06 fd [2] 1a d2 }

  condition:
    any of them
}