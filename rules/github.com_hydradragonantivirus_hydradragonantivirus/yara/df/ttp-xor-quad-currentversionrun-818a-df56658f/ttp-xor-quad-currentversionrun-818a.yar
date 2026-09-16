rule TTP_XOR_QUAD_CurrentVersionRun_818a {
  strings:
    $key_818a = { d2 e5 [2] f6 eb [2] dd c7 [2] f3 e5 [2] e7 fe [2] e8 e4 [2] f6 f9 [2] f4 f8 [2] ef fe [2] f3 f9 [2] ef d6 }

  condition:
    any of them
}