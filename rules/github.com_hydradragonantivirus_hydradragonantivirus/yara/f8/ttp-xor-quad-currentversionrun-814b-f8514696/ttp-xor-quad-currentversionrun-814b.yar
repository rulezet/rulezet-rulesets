rule TTP_XOR_QUAD_CurrentVersionRun_814b {
  strings:
    $key_814b = { d2 24 [2] f6 2a [2] dd 06 [2] f3 24 [2] e7 3f [2] e8 25 [2] f6 38 [2] f4 39 [2] ef 3f [2] f3 38 [2] ef 17 }

  condition:
    any of them
}