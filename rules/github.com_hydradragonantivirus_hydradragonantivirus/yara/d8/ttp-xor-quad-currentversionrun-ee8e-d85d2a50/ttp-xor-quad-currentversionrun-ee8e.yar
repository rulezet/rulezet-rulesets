rule TTP_XOR_QUAD_CurrentVersionRun_ee8e {
  strings:
    $key_ee8e = { bd e1 [2] 99 ef [2] b2 c3 [2] 9c e1 [2] 88 fa [2] 87 e0 [2] 99 fd [2] 9b fc [2] 80 fa [2] 9c fd [2] 80 d2 }

  condition:
    any of them
}