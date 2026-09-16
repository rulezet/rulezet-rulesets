rule TTP_XOR_QUAD_CurrentVersionRun_948a {
  strings:
    $key_948a = { c7 e5 [2] e3 eb [2] c8 c7 [2] e6 e5 [2] f2 fe [2] fd e4 [2] e3 f9 [2] e1 f8 [2] fa fe [2] e6 f9 [2] fa d6 }

  condition:
    any of them
}