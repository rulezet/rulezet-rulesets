rule TTP_XOR_QUAD_CurrentVersionRun_158e {
  strings:
    $key_158e = { 46 e1 [2] 62 ef [2] 49 c3 [2] 67 e1 [2] 73 fa [2] 7c e0 [2] 62 fd [2] 60 fc [2] 7b fa [2] 67 fd [2] 7b d2 }

  condition:
    any of them
}