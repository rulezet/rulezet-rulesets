rule TTP_XOR_QUAD_CurrentVersionRun_1d8e {
  strings:
    $key_1d8e = { 4e e1 [2] 6a ef [2] 41 c3 [2] 6f e1 [2] 7b fa [2] 74 e0 [2] 6a fd [2] 68 fc [2] 73 fa [2] 6f fd [2] 73 d2 }

  condition:
    any of them
}