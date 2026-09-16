rule TTP_XOR_QUAD_CurrentVersionRun_168e {
  strings:
    $key_168e = { 45 e1 [2] 61 ef [2] 4a c3 [2] 64 e1 [2] 70 fa [2] 7f e0 [2] 61 fd [2] 63 fc [2] 78 fa [2] 64 fd [2] 78 d2 }

  condition:
    any of them
}