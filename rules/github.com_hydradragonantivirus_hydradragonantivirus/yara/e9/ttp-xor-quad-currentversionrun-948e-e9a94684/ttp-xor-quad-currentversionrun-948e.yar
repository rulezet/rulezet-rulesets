rule TTP_XOR_QUAD_CurrentVersionRun_948e {
  strings:
    $key_948e = { c7 e1 [2] e3 ef [2] c8 c3 [2] e6 e1 [2] f2 fa [2] fd e0 [2] e3 fd [2] e1 fc [2] fa fa [2] e6 fd [2] fa d2 }

  condition:
    any of them
}