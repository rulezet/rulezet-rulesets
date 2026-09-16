rule TTP_XOR_QUAD_CurrentVersionRun_f78e {
  strings:
    $key_f78e = { a4 e1 [2] 80 ef [2] ab c3 [2] 85 e1 [2] 91 fa [2] 9e e0 [2] 80 fd [2] 82 fc [2] 99 fa [2] 85 fd [2] 99 d2 }

  condition:
    any of them
}