rule TTP_XOR_QUAD_CurrentVersionRun_268e {
  strings:
    $key_268e = { 75 e1 [2] 51 ef [2] 7a c3 [2] 54 e1 [2] 40 fa [2] 4f e0 [2] 51 fd [2] 53 fc [2] 48 fa [2] 54 fd [2] 48 d2 }

  condition:
    any of them
}